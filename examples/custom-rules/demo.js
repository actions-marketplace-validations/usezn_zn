const { evaluate } = require('zn-gate/lib/rules');

// Place .znrules in your project root, and zn-gate automatically loads it:
const res = evaluate("Here is the PROJECT_TITAN_SECRET document");
console.log("Custom rule verdict:", res.verdict, "rule:", res.rule);
