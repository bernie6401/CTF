﻿!function(e){var t={};function i(a){if(t[a])return t[a].exports;var s=t[a]={i:a,l:!1,exports:{}};e[a].call(s.exports,s,s.exports,i);s.l=!0;return s.exports}i.m=e;i.c=t;i.d=function(e,t,a){i.o(e,t)||Object.defineProperty(e,t,{configurable:!1,enumerable:!0,get:a})};i.r=function(e){Object.defineProperty(e,"__esModule",{value:!0})};i.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};i.d(t,"a",t);return t};i.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)};i.p="";i(i.s=5)}([,function(e,t,i){"use strict";i.d(t,"a",function(){return a});class a{static isTrue(e,t){if(!e){t=t?"Internal error. "+t:"Internal error. Unexpectedly false.";a.fail(t)}}static isFalse(e,t){if(e){t=t?"Internal error. "+t:"Internal error. Unexpectedly true.";a.fail(t)}}static isNull(e,t){if(null!==e){t=t?"Internal error. "+t:"Internal error. Unexpectedly not null.";t+=" '"+e+"'";a.fail(t)}}static isUndefined(e,t){0;if(void 0!==e){t=t?"Internal error. "+t:"Internal error. Unexpectedly not undefined.";t+=" '"+e+"'";a.fail(t)}}static hasValue(e,t){if(null===e||void 0===e){t=t?"Internal error. "+t:"Internal error. Unexpectedly "+(null===e?"null":"undefined")+".";a.fail(t)}}static areEqual(e,t,i){e!==t&&a.fail(`Error: ${i}, Unexpectedly not equal- Actual: '${e}', Expected: '${t}'`)}static areNotEqual(e,t,i){e===t&&a.fail(`Error: ${i}, Identical input passed to areNotEqual: '${e}'`)}static failDebugOnly(e){a.fail(e)}static fail(e){var t=new Error((e||"Assert failed.")+"\n");try{throw t}catch(e){e.stack&&(e.description=e.stack);throw e}}}},function(e,t,i){"use strict";i.d(t,"a",function(){return s});var a=i(1);class s{constructor(e,t,i,a,s){this._ourIdentifier=e;this._nextId=0;this._promiseTable={};this._jsonRpcMethodReceive=t;this._jsonRpcNotificationReceive=i;this._postMessage=a;Date.now||(Date.now=function(){return+new Date});s(e=>{this.onMessage(e)})}jsonRpcMethodCall(e,t,i,s,n){i||a.a.failDebugOnly("Trying to insert a promise into the queue without a completed function: The front end will have no way of knowing this promise completed");var o=this._ourIdentifier+"|"+this._nextId;this._nextId++;this._promiseTable[o]={completed:i,error:s};var l=JSON.stringify({id:o,method:e,params:t});if(r.RandomDelay){r.queueData(()=>{this._postMessage(l,n)},l);return!0}return this._postMessage(l,n)}jsonRpcNotification(e,t,i){var a=this._ourIdentifier+"|NULL",s=JSON.stringify({id:a,method:e,params:t});r.RandomDelay?r.queueData(()=>{this._postMessage(s,i)},s):this._postMessage(s,i)}onMessage(e){var t=JSON.parse(e.data),i=t.id.split("|");a.a.areEqual(i.length,2);"NULL"===i[1]?i[0]!==this._ourIdentifier&&this._jsonRpcNotificationReceive(t.method,t.params,t.id):i[0]!==this._ourIdentifier||t.method?r.RandomDelay?r.queueData(()=>{this.handleCall(t)},e.data):this.handleCall(t):r.RandomDelay?r.queueData(()=>{this.handleReply(t)},e.data):this.handleReply(t)}handleReply(e){if(this._promiseTable[e.id]&&this._promiseTable[e.id].completed){if(e.error){a.a.isUndefined(e.data,"Can't have both data and error");this._promiseTable[e.id].error(e.error)}else this._promiseTable[e.id].completed(e.data);delete this._promiseTable[e.id]}else a.a.failDebugOnly("Can't complete a promise that does not exist in the promise table. Probably a dup reply msg.")}handleCall(e){this._jsonRpcMethodReceive(e.method,e.params,(t,i)=>{var a;a=i?JSON.stringify({id:e.id,error:i}):JSON.stringify({id:e.id,data:t});this._postMessage(a)},e.id)}}class n{constructor(e,t){this.callback=e;this.message=t}}class r{static enableDelay(e,t){r.RandomDelay=!0;r.CalculateDelayTime=e;r.DelayedMessage=t}static disableDelay(){r.RandomDelay=!1;if(r.RandomDelayTimeout){clearTimeout(r.RandomDelayTimeout);r.RandomDelayTimeout=null;r.clearQueue()}}static queueData(e,t){var i=new n(e,t);r.DelayedQueue.push(i);if(!r.RandomDelayTimeout){var a=r.CalculateDelayTime(t);r.RandomDelayTimeout=setTimeout(r.fireRandomly,a)}}static fireRandomly(){var e=r.DelayedQueue.shift();r.DelayedMessage(e.message);e.callback();if(r.DelayedQueue.length>0){var t=r.CalculateDelayTime(r.DelayedQueue[0].message);r.RandomDelayTimeout=setTimeout(r.fireRandomly,t)}else r.RandomDelayTimeout=null}static clearQueue(){for(var e=0;e<r.DelayedQueue.length;e++){var t=r.DelayedQueue[e];r.DelayedMessage(t.message);t.callback()}r.DelayedQueue=[]}}r.RandomDelay=!1;r.DelayedQueue=[]},,,function(e,t,i){"use strict";i.r(t);var a;class s{constructor(e){this._messageHandlers=[];this._pendingMessages=[];this._pendingMessagesMap={};this._portId=0;this._uid=0;this.childrenElementLimit=200;this.onDetachCallback=null;this.port=null;this.portReady=!1;this._messageHandlers=e}static getDefaultView(e){return e?void 0!==e.defaultView?e.defaultView:e.parentWindow:null}getUid(){return"uid"+(this._uid++).toString(36)}initialize(e,t,i){this.onDetachCallback=i;browser.addEventListener("documentComplete",this.onDocumentComplete.bind(this));toolUI.addEventListener("detach",this.onDetach.bind(this));toolUI.addEventListener("breakpointhit",this.onBreak.bind(this));++this._portId;this.port=toolUI.createPort(e+this._portId);if(this.port){this.port.addEventListener("message",this.processMessages.bind(this));toolUI.connect(this.port);t()}this._handshakeCallback=t}initializeScriptEngines(e){if(e){if(e.document&&e.document.scripts&&0===e.document.scripts.length)try{Common.RemoteHelpers.executeScript("",e,!0)}catch(e){}if(e.frames)for(var t=0;t<e.frames.length;t++){var i=e.frames[t];if(dom.isWindow(i)){var a=dom.getCrossSiteWindow(e,i);this.initializeScriptEngines(a)}}}}postAllMessages(){for(var e in this._pendingMessagesMap)this._pendingMessages.push(this._pendingMessagesMap[e]);if(this._pendingMessages.length>0){var t=JSON.stringify(this._pendingMessages);this._pendingMessages=[];this._pendingMessagesMap={};try{this.port.postMessage(t)}catch(e){return}}}processMessages(e){if("InitializeDocument"!==e.data)for(var t=e=>{var t=(t,i)=>{this.postObject({uid:e,args:[t]},i)};t.uid=e;return t},i=JSON.parse(e.data),a=0;a<i.length;++a){var s=i[a];if(this._messageHandlers[s.command]){for(var n=s.args,r=0;r<n.length;++r)n[r]&&"callback"===n[r].type&&(n[r]=t(n[r].uid));var o=this._messageHandlers[s.command].apply(this,n);this.postObject({uid:s.uid,args:void 0!==o?[o]:void 0})}}else this._handshakeCallback()}onBreak(){this.postAllMessages()}onDetach(){this._uid=0;this._pendingMessages=[];this._pendingMessagesMap={};this.onDetachCallback&&this.onDetachCallback()}onDocumentComplete(e){if(a){var t=null;if(e)try{e.browserOrWindow&&(e=e.browserOrWindow);e.document?t=e.document:e.Document&&(t=e.Document);var i=s.getDefaultView(t);if(!t||i[a])return;Common.RemoteHelpers.executeScript("",i,!0)}catch(e){}}}postObject(e,t,i=!0){t?this._pendingMessagesMap[t]=e:this._pendingMessages.push(e);this.postAllMessages()}}s.JMCScriptUrl="\\r\\n//# sourceURL=browsertools://browsertools.performance.js";s.InitializeDocumentMaxTries=15;s.InitializeDocumentTries=0;var n,r,o,l,d,c,u=i(2);!function(e){e[e.types=0]="types";e[e.roots=1]="roots";e[e.dominators=2]="dominators"}(n||(n={}));!function(e){e[e.ascending=0]="ascending";e[e.descending=1]="descending"}(r||(r={}));!function(e){e[e.Background=0]="Background";e[e.Foreground=1]="Foreground";e[e.Grid=2]="Grid";e[e.LegendBackground=3]="LegendBackground";e[e.ViewSelection=4]="ViewSelection";e[e.ViewSelectionOutside=5]="ViewSelectionOutside"}(o||(o={}));!function(e){e[e.Foreground=0]="Foreground"}(l||(l={}));!function(e){e[e.Error=-1]="Error";e[e.StreamLength=-2]="StreamLength"}(d||(d={}));!function(e){e[e.Empty=0]="Empty";e[e.Loading=1]="Loading";e[e.Done=2]="Done"}(c||(c={}));i.d(t,"__BROWSERTOOLS_RemoteCode",function(){return h});class h{constructor(){expectedWindowProperty="__BROWSERTOOLS_MEMORYANALYZER_ADDED"}initialize(){browser.addEventListener("beforeScriptExecute",this.onBeforeScriptExecute.bind(this));this._port=toolUI.createPort("memoryAnalyzerPort");toolUI.connect(this._port);this._rpc=new u.a("MEMORYANALYZER_REMOTE_5",(e,t,i)=>this.jsonRpcMethodReceive(e,t,i),(e,t)=>this.jsonRpcNotificationReceive(e,t),e=>{this._port.postMessage(e)},e=>{this._port.addEventListener("message",t=>{e(t)})});this.initializePage();toolUI.addEventListener("detach",this.onDetach.bind(this))}notify(e,t){this._rpc.jsonRpcNotification(e,t)}consoleTakeSnapshot(){this.notify("TakeSnapshot",[])}jsonRpcMethodReceive(e,t,i){var a;(a=t?this[e].apply(this,t):this[e].apply(this))?i(a,void 0):i()}jsonRpcNotificationReceive(e,t){}static appendSnapshotPart(e,t){if(e){var i=JSON.parse(e);!t.version&&i.version&&(t.version=i.version);if(i.data){t.data||(t.data=[]);for(var a=0;a<i.data.length;++a)t.data.push(i.data[a])}!t.privateBytes&&i.privateBytes&&(t.privateBytes=i.privateBytes);!t.pointerSize&&i.pointerSize&&(t.pointerSize=i.pointerSize);!t.base64Image&&i.base64Image&&(t.base64Image=i.base64Image)}}addRemotePageFunctions(e){e[expectedWindowProperty]=browser.createSafeFunction(e,()=>{})}initializePage(){try{var e=s.getDefaultView(browser.document);this.addRemotePageFunctions(e);var t={contextInfo:e.location.href};this.notify("MemoryHandshake",[t]);s.InitializeDocumentTries=0}catch(e){this.onDocumentNotReady()}}onBeforeScriptExecute(e){e&&e.browserOrWindow&&(e=e.browserOrWindow);var t=null;try{t=s.getDefaultView(e.document)}catch(e){return}t===s.getDefaultView(browser.document)&&this.initializePage()}onDetach(){s.InitializeDocumentTries=0;try{var e=s.getDefaultView(browser.document);e[expectedWindowProperty]&&delete e[expectedWindowProperty]}catch(e){}}onDocumentNotReady(){if(s.InitializeDocumentTries<s.InitializeDocumentMaxTries){++s.InitializeDocumentTries;this.notify("DocumentNotYetReady",[])}else this.notify("OnScriptError",["Document Timed Out: Remote.js"])}takeSnapshot(e,t,i,a){try{var n;try{n=browser.takeVisualSnapshot(t,i,a)}catch(e){}var r=resources.memory.processPointerSize,o=resources.memory.processPrivateBytes.toString(),l=n?Math.ceil(n.size/e):0,d=l+1,u="\r\n";if(n){var p=1,m=new FileReader;m.onloadend=(t=>{if(m.readyState===c.Done)try{for(var i,a={base64Image:m.result},s=JSON.stringify(a)+u,r=0;r<l;++r){var o,h=r*e;o=r===l-1?s.length:(r+1)*e;i=[{partId:r+p,data:s.substring(h,o)}];this.notify("SnapshotChunk",i)}}catch(e){var f=[{partId:-1,data:e.message}];this.notify("SnapshotChunk",f)}finally{n.msClose();toolUI.takeMemorySnapshot(this._port.name,"NULL",d)}});m.readAsText(n)}else toolUI.takeMemorySnapshot(this._port.name,"NULL",d);var f=s.getDefaultView(browser.document),g=f.navigator.appName,y=f.navigator.appVersion,v={version:h.SNAPSHOT_VERSION_STRING,timestamp:Date.now(),pointerSize:r,privateBytes:o,clientName:g,clientVersion:y},D=[{partId:0,data:JSON.stringify(v)+u}];this.notify("SnapshotChunk",D);return 0}catch(e){var _=[{partId:-1,data:e.message}];this.notify("SnapshotChunk",_)}}}h.SNAPSHOT_VERSION_STRING="1.1";(new h).initialize()}]);