import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import ts from "./lsp/node_modules/typescript/lib/typescript.js";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const root = path.resolve(input.source_root);

function safePath(relative) {
  const normalized = String(relative || "").replaceAll("\\", "/").replace(/^\.\//, "");
  const absolute = path.resolve(root, normalized);
  if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) {
    fail(`source path escapes root: ${relative}`);
  }
  return { absolute, relative: normalized };
}

function parseFile(relative) {
  const target = safePath(relative);
  const source = fs.readFileSync(target.absolute, "utf8");
  return {
    ...target,
    source,
    file: ts.createSourceFile(
      target.relative,
      source,
      ts.ScriptTarget.Latest,
      true,
      target.relative.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
    ),
  };
}

const parsed = parseFile(input.file);

function nodeText(node, state = parsed) {
  return node ? node.getText(state.file).trim() : "";
}

function span(node, state = parsed) {
  const start = state.file.getLineAndCharacterOfPosition(node.getStart(state.file));
  const end = state.file.getLineAndCharacterOfPosition(node.getEnd());
  return {
    file: state.relative,
    start_line: start.line + 1,
    start_column: start.character + 1,
    end_line: end.line + 1,
    end_column: end.character + 1,
  };
}

function calleeName(node) {
  if (!ts.isCallExpression(node)) return "";
  const callee = node.expression;
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  if (ts.isElementAccessExpression(callee) && callee.argumentExpression) {
    return nodeText(callee.argumentExpression).replace(/^['"]|['"]$/g, "");
  }
  return nodeText(callee);
}

function normalizedAst(node, state = parsed) {
  if (!node) return "";
  function encode(current) {
    const value = { kind: ts.SyntaxKind[current.kind] };
    if (
      ts.isIdentifier(current) ||
      ts.isStringLiteralLike(current) ||
      ts.isNumericLiteral(current) ||
      current.kind === ts.SyntaxKind.TrueKeyword ||
      current.kind === ts.SyntaxKind.FalseKeyword ||
      current.kind === ts.SyntaxKind.NullKeyword
    ) {
      value.text = nodeText(current, state);
    }
    const children = [];
    current.forEachChild((child) => children.push(encode(child)));
    if (children.length) value.children = children;
    return value;
  }
  return JSON.stringify(encode(node));
}

function visit(rootNode, callback) {
  if (!rootNode) return;
  callback(rootNode);
  rootNode.forEachChild((child) => visit(child, callback));
}

function startLine(node, state = parsed) {
  return state.file.getLineAndCharacterOfPosition(node.getStart(state.file)).line + 1;
}

if (input.operation === "call_context") {
  const calls = [];
  visit(parsed.file, (node) => {
    if (ts.isCallExpression(node) && startLine(node) === Number(input.line)) calls.push(node);
  });
  const requestedColumn = Number(input.column || 0);
  const ordered = calls.sort((left, right) => span(left).start_column - span(right).start_column);
  const call = ordered.find((node) => !requestedColumn || span(node).start_column === requestedColumn) || ordered[0];
  if (!call) fail(`cannot locate call at ${input.file}:${input.line}`);

  function localFunctionName(node) {
    if (node.name && ts.isIdentifier(node.name)) return node.name.text;
    const parent = node.parent;
    if (parent && ts.isPropertyAssignment(parent)) return nodeText(parent.name);
    if (parent && ts.isVariableDeclaration(parent)) return nodeText(parent.name);
    return "<anonymous>";
  }

  const functions = [];
  let current = call.parent;
  while (current) {
    if (ts.isFunctionLike(current)) functions.unshift(localFunctionName(current));
    current = current.parent;
  }
  process.stdout.write(`${JSON.stringify({ call_shape: nodeText(call), enclosing_functions: functions })}\n`);
  process.exit(0);
}

const callCandidates = [];
const expressionCandidates = [];
visit(parsed.file, (node) => {
  if (startLine(node) !== Number(input.line)) return;
  if (ts.isCallExpression(node) && (!input.gate_name || calleeName(node) === input.gate_name)) {
    callCandidates.push(node);
  }
  if (
    ts.isBinaryExpression(node) ||
    ts.isPrefixUnaryExpression(node) ||
    ts.isIdentifier(node) ||
    ts.isPropertyAccessExpression(node) ||
    ts.isStringLiteralLike(node)
  ) {
    expressionCandidates.push(node);
  }
});

function byColumn(nodes) {
  const requested = Number(input.column || 0);
  const exact = requested
    ? nodes.filter((node) => span(node).start_column === requested)
    : [];
  return (exact.length ? exact : nodes).sort(
    (left, right) => span(left).start_column - span(right).start_column,
  );
}

const gateNode = byColumn(callCandidates)[0] || byColumn(expressionCandidates)[0];
if (!gateNode) fail(`cannot locate ${input.gate_name} at ${input.file}:${input.line}`);

function ancestor(node, predicate) {
  let current = node;
  while (current) {
    if (predicate(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function functionName(node) {
  if (!node) return "";
  if (node.name && ts.isIdentifier(node.name)) return node.name.text;
  const parent = node.parent;
  if (parent && ts.isPropertyAssignment(parent)) return nodeText(parent.name);
  if (parent && ts.isVariableDeclaration(parent)) return nodeText(parent.name);
  if (parent && ts.isMethodDeclaration(parent)) return nodeText(parent.name);
  return "<anonymous>";
}

const enclosing = ancestor(gateNode, ts.isFunctionLike);

const lexicalOwners = [];
let lexicalNode = enclosing;
while (lexicalNode) {
  if (ts.isFunctionLike(lexicalNode)) lexicalOwners.unshift(functionName(lexicalNode));
  lexicalNode = lexicalNode.parent;
}

function identifiers(node) {
  const result = [];
  const seen = new Set();
  visit(node, (child) => {
    if (ts.isIdentifier(child) && !seen.has(child.text)) {
      seen.add(child.text);
      result.push(child.text);
    }
  });
  return result;
}

function checkedNodeForGate() {
  const candidates = [];
  if (ts.isCallExpression(gateNode)) {
    candidates.push(...gateNode.arguments);
    if (ts.isPropertyAccessExpression(gateNode.expression)) {
      candidates.push(gateNode.expression.expression);
    }
  } else if (ts.isBinaryExpression(gateNode)) {
    candidates.push(gateNode.left, gateNode.right);
  } else if (ts.isPrefixUnaryExpression(gateNode)) {
    candidates.push(gateNode.operand);
  }
  const hinted = String(input.checked_hint || "").trim();
  if (hinted) {
    const exact = candidates.find((candidate) => nodeText(candidate) === hinted);
    if (exact) return exact;
  }
  const checkedLine = Number(input.checked_line || 0);
  const checkedColumn = Number(input.checked_column || 0);
  const located = candidates.find((candidate) => {
    const candidateSpan = span(candidate);
    return (!checkedLine || candidateSpan.start_line === checkedLine) &&
      (!checkedColumn || candidateSpan.start_column === checkedColumn);
  });
  if (located) return located;
  if (ts.isCallExpression(gateNode) && ts.isPropertyAccessExpression(gateNode.expression)) {
    const receiverChecks = new Set([
      "endsWith", "includes", "startsWith", "exists", "isAbsolute", "isFile", "isDirectory",
    ]);
    if (receiverChecks.has(calleeName(gateNode))) return gateNode.expression.expression;
  }
  return candidates[0] || gateNode;
}

const checkedNode = checkedNodeForGate();

function effect(statements) {
  const values = [];
  for (const statement of statements.slice(0, 3)) {
    if (ts.isReturnStatement(statement)) values.push(`return ${nodeText(statement.expression) || "undefined"}`);
    else if (ts.isThrowStatement(statement)) values.push("throw");
    else if (ts.isExpressionStatement(statement)) values.push(nodeText(statement.expression));
    else if (ts.isIfStatement(statement)) values.push(`evaluate nested condition ${nodeText(statement.expression)}`);
    else values.push(ts.SyntaxKind[statement.kind]);
  }
  return values.join("; ") || "continue";
}

function statementList(statement) {
  if (!statement) return [];
  return ts.isBlock(statement) ? [...statement.statements] : [statement];
}

let conditionOwner = ancestor(
  gateNode,
  (node) =>
    (ts.isIfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) &&
    gateNode.getStart() >= node.expression.getStart() && gateNode.getEnd() <= node.expression.getEnd(),
);
let condition = String(input.condition_hint || "");
let contextNode = ancestor(gateNode, ts.isStatement) || gateNode;
let branchEffects = { condition_true: "unknown", condition_false: "unknown" };
if (conditionOwner) {
  condition = nodeText(conditionOwner.expression);
  contextNode = conditionOwner;
  if (ts.isIfStatement(conditionOwner)) {
    branchEffects = {
      condition_true: effect(statementList(conditionOwner.thenStatement)),
      condition_false: effect(statementList(conditionOwner.elseStatement)),
    };
  } else {
    branchEffects = { condition_true: "execute loop body", condition_false: "continue" };
  }
}

const activation = [];
let active = gateNode;
while (active?.parent) {
  const parent = active.parent;
  if (ts.isIfStatement(parent)) {
    if (active.getStart() >= parent.thenStatement.getStart() && active.getEnd() <= parent.thenStatement.getEnd()) {
      activation.push({ condition: nodeText(parent.expression), required_branch: "true" });
    } else if (parent.elseStatement && active.getStart() >= parent.elseStatement.getStart()) {
      activation.push({ condition: nodeText(parent.expression), required_branch: "false" });
    }
  }
  active = parent;
}
activation.reverse();

function sourceChunk(role, symbol, node, state = parsed) {
  return { role, symbol, span: span(node, state), source: nodeText(node, state) };
}

const chunks = [];
const checkedNames = new Set(identifiers(checkedNode));
if (enclosing) {
  const declarations = [];
  visit(enclosing, (node) => {
    if (node.getStart() >= gateNode.getStart()) return;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) declarations.push(node);
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) declarations.push(node);
  });
  const pending = [...checkedNames];
  const emitted = new Set();
  while (pending.length && chunks.length < 16) {
    const name = pending.shift();
    const candidates = declarations.filter((node) => {
      const target = ts.isVariableDeclaration(node) ? node.name.text : node.left.text;
      return target === name;
    });
    const declaration = candidates.sort((a, b) => b.getStart() - a.getStart())[0];
    if (!declaration || emitted.has(declaration.getStart())) continue;
    emitted.add(declaration.getStart());
    const statement = ancestor(declaration, ts.isStatement) || declaration;
    chunks.push(sourceChunk("local-derivation", name, statement));
    const value = ts.isVariableDeclaration(declaration) ? declaration.initializer : declaration.right;
    for (const dependency of identifiers(value)) {
      if (!emitted.has(dependency)) pending.push(dependency);
    }
  }
}
chunks.push(sourceChunk("callsite", input.gate_name || calleeName(gateNode), contextNode));

function functionsNamed(state, name) {
  const matches = [];
  visit(state.file, (node) => {
    if (ts.isFunctionLike(node) && functionName(node) === name) matches.push(node);
  });
  return matches;
}

function relativeImportDefinition(name) {
  let resolved;
  visit(parsed.file, (node) => {
    if (resolved || !ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) return;
    const bindings = node.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) return;
    const element = bindings.elements.find((entry) => entry.name.text === name);
    const specifier = node.moduleSpecifier.text;
    if (!element || !specifier.startsWith(".")) return;
    const importedName = element.propertyName?.text || element.name.text;
    const base = path.resolve(path.dirname(parsed.absolute), specifier);
    const candidates = [];
    if (/\.[cm]?js$/i.test(base)) {
      candidates.push(base.replace(/\.[cm]?js$/i, ".ts"), base.replace(/\.[cm]?js$/i, ".tsx"));
    }
    candidates.push(`${base}.ts`, `${base}.tsx`, path.join(base, "index.ts"));
    const target = candidates.find((candidate) => fs.existsSync(candidate));
    if (!target) return;
    const relative = path.relative(root, target).replaceAll(path.sep, "/");
    const state = parseFile(relative);
    resolved = { state, importedName };
  });
  return resolved;
}

let definition;
let definitionState = parsed;
if (input.definition_file) {
  try {
    definitionState = parseFile(input.definition_file);
    definition = functionsNamed(definitionState, input.gate_name).find(
      (node) => !input.definition_line || startLine(node, definitionState) === Number(input.definition_line),
    );
  } catch {
    definitionState = parsed;
  }
}
if (!definition) {
  const imported = relativeImportDefinition(input.gate_name);
  if (imported) {
    definitionState = imported.state;
    definition = functionsNamed(definitionState, imported.importedName)[0];
  }
}
definition ||= functionsNamed(parsed, input.gate_name)[0];
if (definition && definition !== enclosing) {
  chunks.push(sourceChunk("gate-function", input.gate_name, definition, definitionState));
}

let binding = `${nodeText(checkedNode)} -> unresolved formal`;
let bindingStatus = "unresolved";
if (definition && ts.isCallExpression(gateNode)) {
  const index = gateNode.arguments.findIndex((argument) => argument === checkedNode);
  if (index >= 0 && definition.parameters[index]) {
    binding = `${nodeText(checkedNode)} -> ${nodeText(definition.parameters[index].name, definitionState)}`;
    bindingStatus = "resolved";
  }
}
if (!ts.isCallExpression(gateNode)) {
  binding = `${nodeText(checkedNode)} -> inline expression`;
  bindingStatus = "resolved";
} else if (input.mode === "filter") {
  const callback = gateNode.arguments.find((argument) => ts.isFunctionLike(argument));
  const parameter = callback?.parameters?.[0];
  binding = parameter
    ? `${nodeText(checkedNode)} element -> ${nodeText(parameter.name)}`
    : `${nodeText(checkedNode)} -> filter callback input`;
  bindingStatus = "resolved";
} else if (!definition) {
  const argumentIndex = gateNode.arguments.findIndex((argument) => argument === checkedNode);
  binding = argumentIndex >= 0
    ? `${nodeText(checkedNode)} -> library argument ${argumentIndex}`
    : `${nodeText(checkedNode)} -> library receiver`;
  bindingStatus = "resolved";
}

const result = {
  gate_name: input.gate_name || calleeName(gateNode),
  call_expression: nodeText(gateNode),
  callsite_span: span(gateNode),
  checked_expression: nodeText(checkedNode) || String(input.checked_hint || input.gate_name),
  checked_span: span(checkedNode),
  condition,
  context_source: nodeText(contextNode),
  context_span: span(contextNode),
  branch_effects: branchEffects,
  activation,
  enclosing_function: functionName(enclosing) || String(input.owner_function || ""),
  lexical_owners: lexicalOwners,
  normalized_gate_ast: normalizedAst(gateNode),
  normalized_checked_ast: normalizedAst(checkedNode),
  normalized_context_ast: normalizedAst(contextNode),
  binding,
  binding_status: bindingStatus,
  definition_span: definition ? span(definition, definitionState) : null,
  qualified_function: definition
    ? `${definitionState.relative.replaceAll("/", ".").replace(/\.[^.]+$/, "")}.${input.gate_name}`
    : input.gate_name,
  callee_kind: definition ? "project-function" : ts.isCallExpression(gateNode) ? "library-primitive" : "inline-expression",
  chunks,
};

process.stdout.write(`${JSON.stringify(result)}\n`);
