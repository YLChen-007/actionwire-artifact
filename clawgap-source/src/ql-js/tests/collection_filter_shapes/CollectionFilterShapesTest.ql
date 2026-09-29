import javascript
import call.collection_filters

from string mode, int gateLine, int admissionLine, string checked
where
  exists(DataFlow::CallNode gate, DataFlow::Node checkedNode,
    DataFlow::CallNode admission, string condition |
    collectionAdmissionShape(gate, checkedNode, admission, condition, mode) and
    gateLine = gate.getLocation().getStartLine() and
    admissionLine = admission.getLocation().getStartLine() and
    checked = checkedNode.toString()
  )
  or
  exists(DataFlow::CallNode filter, DataFlow::Node checkedNode, string condition |
    arrayFilterShape(filter, checkedNode, condition) and mode = "array-filter" and
    gateLine = filter.getLocation().getStartLine() and admissionLine = 0 and
    checked = checkedNode.toString()
  )
select mode, gateLine, admissionLine, checked
