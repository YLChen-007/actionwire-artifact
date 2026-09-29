#!/usr/bin/env node
"use strict";

// Static TypeScript schema extraction. This program uses only the compiler API
// vendored for ClawGap's language server; it never imports benchmark modules.

const fs = require("node:fs");
const path = require("node:path");
const ts = require("../gate_semantics/lsp/node_modules/typescript/lib/typescript.js");

function readRequest() {
  return JSON.parse(fs.readFileSync(0, "utf8"));
}

function lineOf(node) {
  return node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function nodeName(node) {
  if (!node || !node.name) return "";
  if (ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name)) return node.name.text;
  return node.name.getText(node.getSourceFile());
}

function unwrap(node) {
  while (
    node &&
    (ts.isAsExpression(node) ||
      ts.isSatisfiesExpression(node) ||
      ts.isParenthesizedExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isTypeAssertionExpression(node))
  ) {
    node = node.expression;
  }
  return node;
}

class Evaluator {
  constructor(program) {
    this.program = program;
    this.checker = program.getTypeChecker();
    this.active = new Set();
    this.consumed = new Set();
  }

  error(node, message) {
    const source = node.getSourceFile();
    const shape = ts.SyntaxKind[node.kind];
    const text = node.getText(source).replace(/\s+/g, " ").slice(0, 400);
    throw new Error(`${source.fileName}:${lineOf(node)}: ${message}; AST=${shape}: ${text}`);
  }

  symbol(node) {
    let symbol = this.checker.getSymbolAtLocation(node);
    if (symbol && symbol.flags & ts.SymbolFlags.Alias) {
      symbol = this.checker.getAliasedSymbol(symbol);
    }
    return symbol;
  }

  declarationForIdentifier(node) {
    const symbol = this.symbol(node);
    if (!symbol) return null;
    let declaration = symbol.valueDeclaration || (symbol.declarations || [])[0] || null;
    if (declaration && ts.isShorthandPropertyAssignment(declaration)) {
      const valueSymbol = this.checker.getShorthandAssignmentValueSymbol(declaration);
      if (valueSymbol) {
        declaration = valueSymbol.valueDeclaration || (valueSymbol.declarations || [])[0] || declaration;
      }
    }
    return declaration;
  }

  evalIdentifier(node, scope) {
    if (scope.has(node.text)) return scope.get(node.text);
    if (node.text === "undefined") return undefined;
    if (node.text === "NaN") return null;
    const declaration = this.declarationForIdentifier(node);
    if (!declaration) this.error(node, `unbound identifier ${JSON.stringify(node.text)}`);
    if (ts.isParameter(declaration)) return undefined;
    let initializer = null;
    if (ts.isVariableDeclaration(declaration) || ts.isPropertyDeclaration(declaration)) {
      initializer = declaration.initializer;
    } else if (ts.isEnumMember(declaration)) {
      initializer = declaration.initializer;
    }
    if (!initializer) this.error(node, `identifier ${JSON.stringify(node.text)} has no static initializer`);
    const key = `${declaration.getSourceFile().fileName}:${declaration.pos}:${node.text}`;
    if (this.active.has(key)) this.error(node, `cyclic static initializer for ${node.text}`);
    this.active.add(key);
    try {
      return this.eval(initializer, scope);
    } finally {
      this.active.delete(key);
    }
  }

  evalObject(node, scope) {
    const result = {};
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        const value = this.eval(property.expression, scope);
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          this.error(property, "object spread is not a static object");
        }
        Object.assign(result, value);
        continue;
      }
      if (ts.isPropertyAssignment(property)) {
        const name = nodeName(property);
        const value = this.eval(property.initializer, scope);
        if (value !== undefined) result[name] = value;
        continue;
      }
      if (ts.isShorthandPropertyAssignment(property)) {
        const value = this.evalIdentifier(property.name, scope);
        if (value !== undefined) result[property.name.text] = value;
        continue;
      }
      if (ts.isMethodDeclaration(property) || ts.isGetAccessorDeclaration(property)) {
        continue;
      }
      this.error(property, "unsupported object property");
    }
    return result;
  }

  evalPropertyAccess(node, scope) {
    const receiver = this.eval(node.expression, scope);
    if (receiver === undefined || receiver === null) {
      if (node.questionDotToken) return undefined;
      this.error(node, "property access on nullish static value");
    }
    if (typeof receiver === "object" && node.name.text in receiver) {
      return receiver[node.name.text];
    }
    if (Array.isArray(receiver) && node.name.text === "length") return receiver.length;
    if (typeof receiver === "string" && node.name.text === "length") return receiver.length;
    this.error(node, `unsupported static property .${node.name.text}`);
  }

  evalElementAccess(node, scope) {
    const receiver = this.eval(node.expression, scope);
    if ((receiver === undefined || receiver === null) && node.questionDotToken) return undefined;
    const key = this.eval(node.argumentExpression, scope);
    if (receiver && (typeof receiver === "object" || typeof receiver === "string")) {
      return receiver[key];
    }
    this.error(node, "unsupported element access");
  }

  evalBinary(node, scope) {
    if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) {
      const left = this.eval(node.left, scope);
      return left === null || left === undefined ? this.eval(node.right, scope) : left;
    }
    if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
      const left = this.eval(node.left, scope);
      return left ? this.eval(node.right, scope) : left;
    }
    if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
      const left = this.eval(node.left, scope);
      return left ? left : this.eval(node.right, scope);
    }
    const left = this.eval(node.left, scope);
    const right = this.eval(node.right, scope);
    switch (node.operatorToken.kind) {
      case ts.SyntaxKind.PlusToken: return left + right;
      case ts.SyntaxKind.MinusToken: return left - right;
      case ts.SyntaxKind.AsteriskToken: return left * right;
      case ts.SyntaxKind.SlashToken: return left / right;
      case ts.SyntaxKind.EqualsEqualsEqualsToken:
      case ts.SyntaxKind.EqualsEqualsToken: return left === right;
      case ts.SyntaxKind.ExclamationEqualsEqualsToken:
      case ts.SyntaxKind.ExclamationEqualsToken: return left !== right;
      case ts.SyntaxKind.GreaterThanToken: return left > right;
      case ts.SyntaxKind.GreaterThanEqualsToken: return left >= right;
      case ts.SyntaxKind.LessThanToken: return left < right;
      case ts.SyntaxKind.LessThanEqualsToken: return left <= right;
      default: this.error(node, "unsupported binary expression");
    }
  }

  typeBox(call, method, args, scope) {
    const values = args.map((arg) => this.eval(arg, scope));
    const options = values[values.length - 1];
    const optionObject = options && typeof options === "object" && !Array.isArray(options)
      ? options : {};
    switch (method) {
      case "String": return { type: "string", ...optionObject };
      case "Number": return { type: "number", ...optionObject };
      case "Integer": return { type: "integer", ...optionObject };
      case "Boolean": return { type: "boolean", ...optionObject };
      case "Null": return { type: "null", ...optionObject };
      case "Unknown":
      case "Any": return { ...optionObject };
      case "Literal": {
        const literal = values[0];
        const kind = literal === null ? "null" : typeof literal;
        const jsonKind = kind === "number" ? "number" : kind;
        return { type: jsonKind, const: literal, ...(values[1] || {}) };
      }
      case "Optional": return { __optional: true, schema: values[0] };
      case "Array": return { type: "array", items: values[0], ...(values[1] || {}) };
      case "Record": return {
        type: "object",
        additionalProperties: values[1],
        ...(values[2] || {}),
      };
      case "Union": return { anyOf: values[0], ...(values[1] || {}) };
      case "Unsafe": return values[0];
      case "Object": {
        const properties = {};
        const required = [];
        for (const [name, value] of Object.entries(values[0] || {})) {
          if (value && value.__optional === true) properties[name] = value.schema;
          else {
            properties[name] = value;
            required.push(name);
          }
        }
        const schema = { type: "object", properties, ...(values[1] || {}) };
        if (required.length) schema.required = required;
        return schema;
      }
      default: this.error(call, `unsupported TypeBox constructor Type.${method}`);
    }
  }

  isZodCall(node) {
    node = unwrap(node);
    while (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const receiver = unwrap(node.expression.expression);
      if (ts.isIdentifier(receiver) && receiver.text === "z") return true;
      node = receiver;
    }
    return false;
  }

  zod(node, scope) {
    node = unwrap(node);
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) {
      this.error(node, "unsupported Zod expression");
    }
    const method = node.expression.name.text;
    const receiverNode = node.expression.expression;
    if (ts.isIdentifier(receiverNode) && receiverNode.text === "z") {
      const args = node.arguments.map((arg) => this.eval(arg, scope));
      let schema;
      let optional = false;
      switch (method) {
        case "string": schema = { type: "string" }; break;
        case "number": schema = { type: "number" }; break;
        case "boolean": schema = { type: "boolean" }; break;
        case "any":
        case "unknown": schema = {}; break;
        case "literal": schema = { const: args[0], type: typeof args[0] }; break;
        case "enum": schema = { type: "string", enum: args[0] }; break;
        case "array": schema = { type: "array", items: this.unwrapZod(args[0]).schema }; break;
        case "tuple": {
          const items = args[0].map((item) => this.unwrapZod(item).schema);
          schema = { type: "array", prefixItems: items, minItems: items.length, maxItems: items.length };
          break;
        }
        case "record": schema = {
          type: "object",
          additionalProperties: this.unwrapZod(args[args.length - 1]).schema,
        }; break;
        case "union": schema = { anyOf: args[0].map((item) => this.unwrapZod(item).schema) }; break;
        case "object": {
          const properties = {};
          const required = [];
          for (const [name, raw] of Object.entries(args[0] || {})) {
            const item = this.unwrapZod(raw);
            properties[name] = item.schema;
            if (!item.optional) required.push(name);
          }
          schema = { type: "object", properties };
          if (required.length) schema.required = required;
          break;
        }
        default: this.error(node, `unsupported Zod constructor z.${method}`);
      }
      return { __zod: true, schema, optional };
    }
    const base = this.zod(receiverNode, scope);
    const result = { __zod: true, schema: { ...base.schema }, optional: base.optional };
    const args = node.arguments.map((arg) => this.eval(arg, scope));
    switch (method) {
      case "optional": result.optional = true; break;
      case "nullable": result.schema = { anyOf: [result.schema, { type: "null" }] }; break;
      case "default": result.optional = true; result.schema.default = args[0]; break;
      case "describe": result.schema.description = args[0]; break;
      case "min": result.schema[result.schema.type === "string" ? "minLength" : "minimum"] = args[0]; break;
      case "max": result.schema[result.schema.type === "string" ? "maxLength" : "maximum"] = args[0]; break;
      case "int": result.schema.type = "integer"; break;
      case "url": result.schema.format = "uri"; break;
      case "strict": result.schema.additionalProperties = false; break;
      case "passthrough": result.schema.additionalProperties = true; break;
      default: this.error(node, `unsupported Zod modifier .${method}()`);
    }
    return result;
  }

  unwrapZod(value) {
    if (!value || value.__zod !== true) throw new Error("expected a statically evaluated Zod schema");
    return value;
  }

  evalLocalFunction(declaration, args, scope, callNode) {
    const child = new Map(scope);
    declaration.parameters.forEach((parameter, index) => {
      const name = parameter.name.getText(declaration.getSourceFile());
      if (index < args.length) child.set(name, args[index]);
      else if (parameter.initializer) child.set(name, this.eval(parameter.initializer, child));
      else child.set(name, undefined);
    });
    const run = (statements) => {
      for (const statement of statements) {
        if (ts.isVariableStatement(statement)) {
          for (const declarationNode of statement.declarationList.declarations) {
            if (!ts.isIdentifier(declarationNode.name) || !declarationNode.initializer) {
              this.error(declarationNode, "unsupported local variable declaration");
            }
            child.set(declarationNode.name.text, this.eval(declarationNode.initializer, child));
          }
          continue;
        }
        if (ts.isIfStatement(statement)) {
          const branch = this.eval(statement.expression, child)
            ? statement.thenStatement : statement.elseStatement;
          if (branch) {
            const nested = ts.isBlock(branch) ? branch.statements : [branch];
            const returned = run(nested);
            if (returned.done) return returned;
          }
          continue;
        }
        if (ts.isExpressionStatement(statement) && ts.isDeleteExpression(statement.expression)) {
          const target = statement.expression.expression;
          if (!ts.isPropertyAccessExpression(target)) this.error(target, "unsupported delete target");
          const receiver = this.eval(target.expression, child);
          delete receiver[target.name.text];
          continue;
        }
        if (ts.isReturnStatement(statement) && statement.expression) {
          return { done: true, value: this.eval(statement.expression, child) };
        }
        this.error(statement, "unsupported statement in static schema builder");
      }
      return { done: false };
    };
    if (!declaration.body || !ts.isBlock(declaration.body)) this.error(callNode, "schema builder has no block body");
    const returned = run(declaration.body.statements);
    if (!returned.done) this.error(callNode, "schema builder has no static return");
    return returned.value;
  }

  evalCall(node, scope) {
    const expression = node.expression;
    if (ts.isPropertyAccessExpression(expression)) {
      const receiverText = expression.expression.getText(node.getSourceFile());
      if (receiverText === "Type") {
        return this.typeBox(node, expression.name.text, [...node.arguments], scope);
      }
      if (this.isZodCall(node)) return this.zod(node, scope);
      if (expression.name.text === "join") {
        const receiver = this.eval(expression.expression, scope);
        const separator = node.arguments.length ? this.eval(node.arguments[0], scope) : ",";
        if (!Array.isArray(receiver)) this.error(node, "only Array.join is statically supported");
        return receiver.join(separator);
      }
    }
    if (ts.isIdentifier(expression)) {
      if (expression.text === "zodSchema") {
        return this.unwrapZod(this.eval(node.arguments[0], scope)).schema;
      }
      if (expression.text === "tool") return this.eval(node.arguments[0], scope);
      if (expression.text === "stringEnum" || expression.text === "optionalStringEnum") {
        const values = this.eval(node.arguments[0], scope);
        const options = node.arguments[1] ? this.eval(node.arguments[1], scope) : {};
        const schema = { type: "string", enum: [...values], ...options };
        return expression.text === "optionalStringEnum"
          ? { __optional: true, schema } : schema;
      }
      const declaration = this.declarationForIdentifier(expression);
      if (declaration && ts.isFunctionDeclaration(declaration)) {
        const args = node.arguments.map((arg) => this.eval(arg, scope));
        return this.evalLocalFunction(declaration, args, scope, node);
      }
    }
    this.error(node, "unsupported static call");
  }

  eval(node, scope = new Map()) {
    node = unwrap(node);
    this.consumed.add(node.getSourceFile().fileName);
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (node.kind === ts.SyntaxKind.NullKeyword) return null;
    if (ts.isIdentifier(node)) return this.evalIdentifier(node, scope);
    if (ts.isArrayLiteralExpression(node)) return node.elements.map((item) => this.eval(item, scope));
    if (ts.isObjectLiteralExpression(node)) return this.evalObject(node, scope);
    if (ts.isPropertyAccessExpression(node)) return this.evalPropertyAccess(node, scope);
    if (ts.isElementAccessExpression(node)) return this.evalElementAccess(node, scope);
    if (ts.isBinaryExpression(node)) return this.evalBinary(node, scope);
    if (ts.isConditionalExpression(node)) {
      return this.eval(node.condition, scope) ? this.eval(node.whenTrue, scope) : this.eval(node.whenFalse, scope);
    }
    if (ts.isPrefixUnaryExpression(node)) {
      const value = this.eval(node.operand, scope);
      if (node.operator === ts.SyntaxKind.ExclamationToken) return !value;
      if (node.operator === ts.SyntaxKind.MinusToken) return -value;
      if (node.operator === ts.SyntaxKind.PlusToken) return +value;
      this.error(node, "unsupported unary expression");
    }
    if (ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (ts.isTemplateExpression(node)) {
      let text = node.head.text;
      for (const span of node.templateSpans) {
        text += String(this.eval(span.expression, scope)) + span.literal.text;
      }
      return text;
    }
    if (ts.isCallExpression(node)) {
      if (this.isZodCall(node)) return this.zod(node, scope);
      return this.evalCall(node, scope);
    }
    this.error(node, "unsupported static expression");
  }

  identifier(sourceFile, name) {
    let found = null;
    const visit = (node) => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.name.text === name &&
        node.initializer
      ) found = node.initializer;
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    if (!found) throw new Error(`${sourceFile.fileName}: identifier ${JSON.stringify(name)} not found`);
    const value = this.eval(found);
    return value && value.__zod ? value.schema : value;
  }
}

function getProperty(object, name) {
  for (const property of object.properties) {
    if ((ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) && nodeName(property) === name) {
      return ts.isShorthandPropertyAssignment(property) ? property.name : property.initializer;
    }
  }
  return null;
}

function findHandlerObject(sourceFile, line, handlerName) {
  const candidates = [];
  const visit = (node) => {
    if (ts.isObjectLiteralExpression(node)) {
      const handler = node.properties.find((property) =>
        (ts.isMethodDeclaration(property) || ts.isPropertyAssignment(property)) &&
        nodeName(property) === handlerName &&
        lineOf(property) === line
      );
      if (handler) candidates.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  if (!candidates.length) {
    throw new Error(`${sourceFile.fileName}:${line}: no ${handlerName} property at handler line`);
  }
  return candidates.sort((a, b) => (a.end - a.pos) - (b.end - b.pos))[0];
}

function findVariableInitializer(sourceFile, name) {
  let result = null;
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
      result = node.initializer || null;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return result;
}

function leadingDescription(sourceFile, line, handlerName) {
  let target = null;
  const visit = (node) => {
    if (
      (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) &&
      node.name && nodeName(node) === handlerName && lineOf(node) === line
    ) target = node;
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  if (!target) return `Structured-output action handled by ${handlerName}.`;
  const ranges = ts.getLeadingCommentRanges(sourceFile.text, target.getFullStart()) || [];
  const comment = ranges.length ? sourceFile.text.slice(ranges[ranges.length - 1].pos, ranges[ranges.length - 1].end) : "";
  const clean = comment
    .replace(/^\/\*\*?/, "")
    .replace(/\*\/$/, "")
    .split(/\r?\n/)
    .map((part) => part.replace(/^\s*\*\s?/, "").trim())
    .filter(Boolean)
    .join(" ");
  return clean || `Structured-output action handled by ${handlerName}.`;
}

function main() {
  const request = readRequest();
  const roots = [...new Set(request.requests.flatMap((item) => {
    const files = [path.resolve(request.sourceRoot, item.file)];
    if (item.schemaFile) files.push(path.resolve(request.sourceRoot, item.schemaFile));
    return files;
  }))];
  const program = ts.createProgram({
    rootNames: roots,
    options: {
      target: ts.ScriptTarget.ESNext,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      allowJs: false,
      skipLibCheck: true,
      noEmit: true,
    },
  });
  const evaluator = new Evaluator(program);
  const results = [];
  for (const item of request.requests) {
    const fileName = path.resolve(request.sourceRoot, item.file);
    const sourceFile = program.getSourceFile(fileName);
    if (!sourceFile) throw new Error(`${fileName}: compiler API did not load source file`);
    evaluator.consumed = new Set([fileName]);
    if (item.mode === "structured-output") {
      const schemaFileName = path.resolve(request.sourceRoot, item.schemaFile);
      const schemaFile = program.getSourceFile(schemaFileName);
      if (!schemaFile) throw new Error(`${schemaFileName}: compiler API did not load schema file`);
      const result = {
        tool_name: item.tool_name,
        description: leadingDescription(sourceFile, item.line, item.handler_func),
        parameters: evaluator.identifier(schemaFile, item.schemaIdentifier),
        definition_line: item.line,
        schema_file: item.schemaFile,
        schema_line: lineOf(findVariableInitializer(schemaFile, item.schemaIdentifier)),
      };
      result.consumed_files = [...evaluator.consumed]
        .map((used) => path.relative(request.sourceRoot, used).split(path.sep).join("/"))
        .sort();
      results.push(result);
      continue;
    }
    let object = findHandlerObject(sourceFile, item.line, item.handler_func);
    let definition = object;
    let nestedTool = getProperty(object, "tool");
    if (nestedTool) {
      nestedTool = unwrap(nestedTool);
      if (!ts.isObjectLiteralExpression(nestedTool)) evaluator.error(nestedTool, "MCP tool metadata is not a literal object");
      definition = nestedTool;
    }
    let nameNode = getProperty(definition, "name");
    let descriptionNode = getProperty(definition, "description");
    let parametersNode = getProperty(definition, "parameters") || getProperty(definition, "inputSchema");
    if (item.tool_name === "message") {
      parametersNode = findVariableInitializer(sourceFile, "MessageToolSchema");
      const descriptionFunction = sourceFile.statements.find((node) =>
        ts.isFunctionDeclaration(node) && node.name && node.name.text === "buildMessageToolDescription"
      );
      if (!descriptionFunction || !descriptionFunction.body) throw new Error(`${fileName}: message description builder not found`);
      const returns = [];
      const collect = (node) => { if (ts.isReturnStatement(node) && node.expression) returns.push(node.expression); ts.forEachChild(node, collect); };
      collect(descriptionFunction.body);
      descriptionNode = returns[returns.length - 1];
    }
    if (!descriptionNode || !parametersNode) {
      throw new Error(`${fileName}:${item.line}: tool object lacks description or parameter schema`);
    }
    let description;
    try {
      description = evaluator.eval(descriptionNode);
    } catch (error) {
      const unwrapped = unwrap(descriptionNode);
      if (ts.isConditionalExpression(unwrapped)) description = evaluator.eval(unwrapped.whenFalse);
      else throw error;
    }
    const parametersValue = evaluator.eval(parametersNode);
    const parameters = parametersValue && parametersValue.__zod ? parametersValue.schema : parametersValue;
    const declaredName = nameNode ? evaluator.eval(nameNode) : item.tool_name;
    let schemaDefinitionNode = unwrap(parametersNode);
    if (ts.isIdentifier(schemaDefinitionNode)) {
      const declaration = evaluator.declarationForIdentifier(schemaDefinitionNode);
      if (
        declaration &&
        (ts.isVariableDeclaration(declaration) || ts.isPropertyDeclaration(declaration)) &&
        declaration.initializer
      ) {
        schemaDefinitionNode = unwrap(declaration.initializer);
      }
    }
    const result = {
      tool_name: item.tool_name,
      declared_name: declaredName,
      description,
      parameters,
      definition_line: lineOf(definition),
      schema_file: path.relative(request.sourceRoot, schemaDefinitionNode.getSourceFile().fileName).split(path.sep).join("/"),
      schema_line: lineOf(schemaDefinitionNode),
    };
    result.consumed_files = [...evaluator.consumed]
      .map((used) => path.relative(request.sourceRoot, used).split(path.sep).join("/"))
      .sort();
    results.push(result);
  }
  process.stdout.write(JSON.stringify({ results }));
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error && error.stack ? error.stack : error}\n`);
  process.exit(1);
}
