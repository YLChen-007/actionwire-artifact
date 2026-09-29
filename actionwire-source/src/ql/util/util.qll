/**
 * clawgap util library (hermes 适配版，基于 AgentFuzz ql/util/util.qll)
 *
 * 与 AgentFuzz 的差异：
 *   - getBlacklist() 改为 hermes 专用：排除 tests / 已 vendored 的依赖 / 文档站点。
 *   - getDepthLimit() 收紧为 [2..8]，配合 call.qll 的 CHA 增强边控制图规模。
 *
 * SPEC（管辖文档，见 docs-map.yaml）：design/hermes-agent/call-chain/call_chain_hermes-design.md
 */

import python
import project.ProjectModel

// 位置黑名单：按 location.toString() 的子串过滤，掉测试/依赖/文档。
// 注意：.venv / node_modules 已在 codeql database create 阶段用 LGTM_INDEX_FILTERS
// 排除，这里再做一层兜底，并额外排除 tests 与文档站点。
predicate isIncludeLocation2(Location loc) { isIncludeLocationStr(loc.toString()) }

bindingset[s]
predicate isIncludeLocationStr(string s) {
  forall(string black | black = getBlacklist() | not s.matches("%" + black + "%")) and
  not projectExcludedLocationString(s)
}

string getBlacklist() {
  result =
    [
      "/tests/", "/test_", "_test.py", "conftest",
      "node_modules", ".venv", "site-packages", "miniconda", "__pycache__",
      "/docs/", "/website/", "/locales/", "/example", "/demo"
    ]
}

string locStr(Location loc) {
  result =
    loc.getFile().getAbsolutePath() + "#" + loc.getStartLine().toString() + ":" +
      loc.getStartColumn().toString() + "#" + loc.getEndLine().toString() + ":" +
      loc.getEndColumn().toString()
}

string getStrFuncName() { result = ["split", "index", "rindex"] }

// 调用链最大深度。terminal→Popen 约 4 跳；但文件工具链
// （write_file_tool→file_ops.write_file→_atomic_write→_exec→env.execute→execute→_run_bash→Popen）
// 约 7 跳，故上限取 8。定向桥已限制 CHA 规模，深度 8 仍可控。
int getDepthLimit() { result = [2 .. 8] }
