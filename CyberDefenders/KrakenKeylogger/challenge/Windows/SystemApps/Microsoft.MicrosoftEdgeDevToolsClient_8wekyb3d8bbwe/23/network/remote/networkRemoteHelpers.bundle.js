﻿!function(e){var t={};function s(i){if(t[i])return t[i].exports;var n=t[i]={i:i,l:!1,exports:{}};e[i].call(n.exports,n,n.exports,s);n.l=!0;return n.exports}s.m=e;s.c=t;s.d=function(e,t,i){s.o(e,t)||Object.defineProperty(e,t,{configurable:!1,enumerable:!0,get:i})};s.r=function(e){Object.defineProperty(e,"__esModule",{value:!0})};s.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};s.d(t,"a",t);return t};s.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)};s.p="";s(s.s=3)}({3:function(e,t,s){"use strict";s.r(t);s.d(t,"default",function(){return n});var i;class n{constructor(e){this._messageHandlers=[];this._pendingMessages=[];this._pendingMessagesMap={};this._portId=0;this._uid=0;this.childrenElementLimit=200;this.onDetachCallback=null;this.port=null;this.portReady=!1;this._messageHandlers=e}static getDefaultView(e){return e?void 0!==e.defaultView?e.defaultView:e.parentWindow:null}getUid(){return"uid"+(this._uid++).toString(36)}initialize(e,t,s){this.onDetachCallback=s;browser.addEventListener("documentComplete",this.onDocumentComplete.bind(this));toolUI.addEventListener("detach",this.onDetach.bind(this));toolUI.addEventListener("breakpointhit",this.onBreak.bind(this));++this._portId;this.port=toolUI.createPort(e+this._portId);if(this.port){this.port.addEventListener("message",this.processMessages.bind(this));toolUI.connect(this.port);t()}this._handshakeCallback=t}initializeScriptEngines(e){if(e&&e.frames)for(var t=0;t<e.frames.length;t++){var s=e.frames[t];if(dom.isWindow(s)){var i=dom.getCrossSiteWindow(e,s);this.initializeScriptEngines(i)}}}postAllMessages(){for(var e in this._pendingMessagesMap)this._pendingMessages.push(this._pendingMessagesMap[e]);if(this._pendingMessages.length>0){var t=JSON.stringify(this._pendingMessages);this._pendingMessages=[];this._pendingMessagesMap={};try{this.port.postMessage(t)}catch(e){return}}}processMessages(e){if("InitializeDocument"!==e.data)for(var t=e=>(t,s)=>{this.postObject({uid:e,args:[t]},s)},s=JSON.parse(e.data),i=0;i<s.length;++i){var n=s[i];if(this._messageHandlers[n.command]){for(var a=n.args,r=0;r<a.length;++r)a[r]&&"callback"===a[r].type&&(a[r]=t(a[r].uid));var o=this._messageHandlers[n.command].apply(this,a);this.postObject({uid:n.uid,args:void 0!==o?[o]:void 0})}}else this._handshakeCallback()}onBreak(){this.postAllMessages()}onDetach(){this._uid=0;this._pendingMessages=[];this._pendingMessagesMap={};this.onDetachCallback&&this.onDetachCallback()}onDocumentComplete(e){if(i){var t=null;if(e)try{e.browserOrWindow&&(e=e.browserOrWindow);e.document?t=e.document:e.Document&&(t=e.Document);var s=n.getDefaultView(t);if(!t||s[i])return;Common.RemoteHelpers.executeScript("",s,!0)}catch(e){}}}postObject(e,t,s=!0){t?this._pendingMessagesMap[t]=e:this._pendingMessages.push(e);this.postAllMessages()}}n.JMCScriptUrl="\\r\\n//# sourceURL=browsertools://browsertools.performance.js";n.InitializeDocumentTries=0;n.InitializeDocumentMaxTries=15}});