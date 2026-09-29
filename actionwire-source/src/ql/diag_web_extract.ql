/**
 * @id clawgap/diag-web-extract
 * @name diag: web_extract embedded-secret gate — why (A) non-dominance
 * @description 检验 web_extract_tool 里 `if _PREFIX_RE.search(...)` 是否支配 sink-ward 调用
 *              provider.extract；对照它是否支配同一 for 循环体内的 append（回路旁路假设）。
 * @kind table
 * @tags clawgap
 */

import python

// web_extract_tool 作用域
Function webExtract() { result.getName() = "web_extract_tool" }

// `_PREFIX_RE.search(...)` 调用节点
CallNode searchCall() {
  result.getScope() = webExtract() and
  result.getFunction().(AttrNode).getName() = "search"
}

// sink-ward: provider.extract(...)
CallNode extractCall() {
  result.getScope() = webExtract() and
  result.getFunction().(AttrNode).getName() = "extract"
}

// 分类 sink 之后可能相关的 append（同 for 体内）
CallNode appendCall() {
  result.getScope() = webExtract() and
  result.getFunction().(AttrNode).getName() = "append"
}

from string q, string answer
where
  // (1) 存在包含 search 的 ConditionBlock 吗？
  q = "P1: exists ConditionBlock whose test AST contains _PREFIX_RE.search" and
  (
    if
      exists(ConditionBlock cb, CallNode sc |
        sc = searchCall() and
        cb.getScope() = webExtract() and
        sc.getNode() = cb.getLastNode().getNode().(Expr).getASubExpression*()
      )
    then answer = "YES"
    else answer = "NO"
  )
  or
  // (2) 该 ConditionBlock 是否支配 provider.extract 的基本块？（预期 NO —— 回路出边旁路）
  q = "P2: secret-check ConditionBlock CONTROLS provider.extract basic block" and
  (
    if
      exists(ConditionBlock cb, CallNode sc, CallNode ex |
        sc = searchCall() and ex = extractCall() and
        cb.getScope() = webExtract() and
        sc.getNode() = cb.getLastNode().getNode().(Expr).getASubExpression*() and
        cb.controls(ex.getBasicBlock(), _)
      )
    then answer = "YES"
    else answer = "NO"
  )
  or
  // (3) 同一 ConditionBlock 是否支配 for 体内的 append（对照：机制本身工作，坏在回路）
  q = "P3: secret-check ConditionBlock CONTROLS in-loop append basic block" and
  (
    if
      exists(ConditionBlock cb, CallNode sc, CallNode ap |
        sc = searchCall() and ap = appendCall() and
        cb.getScope() = webExtract() and
        sc.getNode() = cb.getLastNode().getNode().(Expr).getASubExpression*() and
        cb.controls(ap.getBasicBlock(), _)
      )
    then answer = "YES"
    else answer = "NO"
  )
  or
  // (4) provider.extract 是否与 secret-check 在同一 BasicBlock？（排除同块特例）
  q = "P4: provider.extract shares basic block with secret-check" and
  (
    if
      exists(ConditionBlock cb, CallNode sc, CallNode ex |
        sc = searchCall() and ex = extractCall() and
        cb.getScope() = webExtract() and
        sc.getNode() = cb.getLastNode().getNode().(Expr).getASubExpression*() and
        ex.getBasicBlock() = cb
      )
    then answer = "YES"
    else answer = "NO"
  )
select q, answer
