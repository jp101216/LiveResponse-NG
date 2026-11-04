"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const page = fs.readFileSync(path.join(__dirname,"..","lrng-viewer.html"),"utf8");
const start=page.indexOf("  function evidenceGraph() {");
const end=page.indexOf("  function focusGraph(",start);
assert.ok(start>=0 && end>start,"the actual graph model must be found");

function graph(records, sources) {
  const result={name:"evidence_graph",records:records.map((fields)=>({fields})),meta:{}};
  const model={results:sources,byName:new Map([["evidence_graph",result]])};
  return vm.runInNewContext(`(() => { const plain=(x)=>typeof x==="string"?x:String(x??""); const isObj=(x)=>x!==null&&typeof x==="object"&&!Array.isArray(x); ${page.slice(start,end)} return evidenceGraph(); })()`,{model});
}
const source=(sourceIndex,name="processes")=>({sourceIndex,name,records:[{fields:{pid:1},findings:[]}]});
const node=(id,result=3,record=0)=>({kind:"node",id,label:"</script><script>alert(1)</script>",source_collector:"processes",source_ref:{result,record}});
const edge=(from,to,basis="inferred")=>({kind:"edge",from,to,basis,relation:"same_pid",explanation:"untrusted text"});

test("graph references retain original indices after invalid report results are omitted",()=>{
  const g=graph([node("a"),node("b",7),edge("a","b")],[source(3),source(7)]);
  assert.equal(g.nodes.size,2); assert.equal(g.edges.length,1);
  assert.equal(g.nodes.get("a").ri,0); assert.equal(g.nodes.get("b").ri,1);
  assert.equal(g.bySource.get("1:0").id,"b");
  assert.equal(g.nodes.get("a").label,node("a").label);
});
test("invalid and ambiguous references, duplicate IDs and foreign endpoints are omitted",()=>{
  const wrong=node("wrong");wrong.source_collector="network";
  const g=graph([node("a"),node("a"),node("missing",99),node("negative",3,-1),wrong,edge("a","foreign"),edge("a","a")],[source(3)]);
  assert.equal(g.nodes.size,1);assert.equal(g.edges.length,0);assert.equal(g.rejected,6);
});
test("only explicitly observed or inferred edges enter the graph",()=>{
  const g=graph([node("a"),node("b",7),edge("a","b","verified"),edge("a","b","observed"),edge("b","a")],[source(3),source(7)]);
  assert.equal(g.edges.length,2);assert.equal(g.rejected,1);
  assert.equal(g.adjacent.get("a").length,2);
});
test("graph budgets reject excessive nodes without expanding sparse references",()=>{
  const records=Array.from({length:5010},(_,i)=>node("n"+i));
  records.push(node("sparse",3,1e12));
  const g=graph(records,[source(3)]);
  assert.equal(g.nodes.size,5000);assert.equal(g.rejected,11);
});
