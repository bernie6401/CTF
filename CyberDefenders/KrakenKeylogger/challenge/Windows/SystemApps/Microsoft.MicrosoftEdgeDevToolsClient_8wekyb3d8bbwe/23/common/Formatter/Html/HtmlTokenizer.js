﻿var Common;!function(t){!function(t){!function(e){"use strict";class s extends t.StateMachine{constructor(t){super();this._pos=0;this._contentPos=0;this._tokenQueue=[];this._isInRawTag=!1;this._isInTagAttributes=!1;this._source=t;this.pushStates(this.stateScanTrivia,this.stateScanDocumentSyntax)}next(){for(;this.runUntil(this.markSendTokens);)if(this._tokenQueue.length){this.collapseRuns();var t=this._tokenQueue.shift();this._tokenQueue.length&&this.pushState(this.markSendTokens);return{value:t,done:!1}}return{done:!0}}readChar(){return this._source.charCodeAt(this._pos++)}enqueueToken(t){if(!this._isInRawTag){this._tokenQueue.push(t);this._contentPos=this._pos}}enqueueContent(t){!this._isInRawTag&&t>this._contentPos&&this.enqueueToken(this.createToken(16,this._contentPos,t))}enqueueTrivia(t){!this._isInRawTag&&t>this._contentPos&&this.enqueueToken(this.createToken(17,this._contentPos,t))}collapseRuns(){var t;do{for(var e=(t=this._tokenQueue.length)-1;e>=0;){var s=this._tokenQueue[e];if(17===s.kind){if(e>0){if(17===(i=this._tokenQueue[e-1]).kind){i.end=s.end;this._tokenQueue.splice(e,1)}else if(16===i.kind&&e<this._tokenQueue.length-1){var a=this._tokenQueue[e+1];if(16===a.kind){i.end=a.end;this._tokenQueue.splice(e,2)}}}}else if(16===s.kind&&e>0){var i;if(16===(i=this._tokenQueue[e-1]).kind){i.end=s.end;this._tokenQueue.splice(e,1)}}e--}}while(this._tokenQueue.length!==t)}markSendTokens(){}stateScanDocumentSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else{this.pushState(this.stateScanDocumentSyntax);if(60===e){e=this.readChar();if(this.lookaheadOpenProcessingInstruction(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(4,t,t+2));this.enqueueToken(this.createToken(10,t+2,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia,this.stateScanProcessingInstructionSyntax)}else if(33===e){e=this.readChar();if(this.lookaheadMinusMinus(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(0,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanCommentSyntax)}else if(this.lookaheadOpenCharacterData(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(2,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanCharacterDataSyntax)}else if(this.lookaheadDocumentType(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(6,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia,this.stateScanDocumentTypeSyntax)}}else if(this.lookaheadScript(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(8,t,t+1));this.enqueueToken(this.createToken(10,t+1,this._pos));this.pushStates(this.markSendTokens,this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes,this.stateEnterRawTag,this.stateScanScriptSyntax,this.stateExitRawTag)}else if(this.lookaheadStyle(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(8,t,t+1));this.enqueueToken(this.createToken(10,t+1,this._pos));this.pushStates(this.markSendTokens,this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes,this.stateEnterRawTag,this.stateScanStyleSyntax,this.stateExitRawTag)}else if(this.lookaheadTitle(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(8,t,t+1));this.enqueueToken(this.createToken(10,t+1,this._pos));this.pushStates(this.markSendTokens,this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes,this.stateEnterRawTag,this.stateScanTitleSyntax,this.stateExitRawTag)}else if(this.lookaheadTextarea(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(8,t,t+1));this.enqueueToken(this.createToken(10,t+1,this._pos));this.pushStates(this.markSendTokens,this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes,this.stateEnterRawTag,this.stateScanTextAreaSyntax,this.stateExitRawTag)}else if(this.lookaheadRun(e,r,u)){this.enqueueContent(t);this.enqueueToken(this.createToken(8,t,t+1));this.enqueueToken(this.createToken(10,t+1,this._pos));this.pushStates(this.markSendTokens,this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes)}else if(47===e&&this.lookaheadRun(this.readChar(),r,u)){this.enqueueContent(t);this.enqueueToken(this.createToken(9,t,t+2));this.enqueueToken(this.createToken(10,t+2,this._pos));this.pushStates(this.markSendTokens,this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes)}}else if(this.lookaheadRun(e,c)){this.enqueueContent(t);this.enqueueToken(this.createToken(17,t,this._pos))}}}stateScanCommentSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this.lookaheadCloseComment(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(1,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia)}else this.pushState(this.stateScanCommentSyntax)}stateScanCharacterDataSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this.lookaheadCloseCharacterData(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(3,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia)}else this.pushState(this.stateScanCharacterDataSyntax)}stateScanProcessingInstructionSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this.lookaheadCloseProcessingInstruction(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(5,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia)}else this.pushState(this.stateScanProcessingInstructionSyntax)}stateScanDocumentTypeSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(62===e){this.enqueueContent(t);this.enqueueToken(this.createToken(7,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia)}else this.pushState(this.stateScanDocumentTypeSyntax)}stateEnterTagAttributes(){this._isInTagAttributes=!0}stateExitTagAttributes(){this._isInTagAttributes=!1}stateEnterRawTag(){this._isInRawTag=!0}stateExitRawTag(){this._isInRawTag=!1;this.enqueueContent(this._pos);this.pushState(this.markSendTokens)}stateScanScriptSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this._isInRawTag=!1;this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else this.lookaheadOpenComment(e)?this.pushStates(this.stateScanScriptCommentSyntax,this.stateScanScriptSyntax):this.lookaheadOpenEndTag(e,t=>this.lookaheadScript(t))?this._pos=t:this.pushState(this.stateScanScriptSyntax)}stateScanScriptCommentSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this._isInRawTag=!1;this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else this.lookaheadOpenStartTag(e,t=>this.lookaheadScript(t))?this.pushStates(this.stateEnterTagAttributes,this.stateScanTrivia,this.stateScanTagSyntax,this.stateExitTagAttributes,this.stateScanScriptSyntax,this.stateScanScriptCommentSyntax):this.lookaheadOpenEndTag(e,t=>this.lookaheadScript(t))?this._pos=t:this.lookaheadCloseComment(e)||this.pushState(this.stateScanScriptCommentSyntax)}stateScanStyleSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this._isInRawTag=!1;this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else this.lookaheadOpenComment(e)?this.pushStates(this.stateScanStyleCommentSyntax,this.stateScanStyleSyntax):this.lookaheadOpenEndTag(e,t=>this.lookaheadStyle(t))?this._pos=t:this.pushState(this.stateScanStyleSyntax)}stateScanStyleCommentSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this._isInRawTag=!1;this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else this.lookaheadOpenEndTag(e,t=>this.lookaheadStyle(t))?this._pos=t:this.lookaheadCloseComment(e)||this.pushState(this.stateScanStyleCommentSyntax)}stateScanTitleSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this._isInRawTag=!1;this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else this.lookaheadOpenEndTag(e,t=>this.lookaheadTitle(t))?this._pos=t:this.pushState(this.stateScanTitleSyntax)}stateScanTextAreaSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this._isInRawTag=!1;this.enqueueContent(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else this.lookaheadOpenEndTag(e,t=>this.lookaheadTextarea(t))?this._pos=t:this.pushState(this.stateScanTextAreaSyntax)}stateScanTagSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this.lookaheadRun(e,S)){this.enqueueToken(this.createToken(12,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia,this.stateScanAttributeSyntax,this.stateScanTagSyntax)}else if(this.lookaheadCloseStartOrEndTag(e)){this.enqueueToken(this.createToken(11,t,this._pos));this.pushStates(this.markSendTokens,this.stateExitTagAttributes,this.stateScanTrivia)}else{this.enqueueToken(this.createToken(17,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTagSyntax)}}stateScanAttributeSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(61===e){this.enqueueToken(this.createToken(14,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia,this.stateScanAttributeValueAssignmentSyntax)}else{this._pos=t;this.pushState(this.stateScanTrivia)}}stateScanAttributeValueAssignmentSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this.lookaheadCloseStartOrEndTag(e)){this._pos=t;this.pushState(this.stateScanTrivia)}else{if(34===e||39===e){this._contentPos=t;this._quoteChar=e}else this._pos=t;this.pushStates(this.stateScanAttributeValueSyntax)}}stateScanAttributeValueSyntax(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this._quoteChar)if(e===this._quoteChar){this._quoteChar=void 0;this.enqueueToken(this.createToken(13,this._contentPos,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia)}else this.pushState(this.stateScanAttributeValueSyntax);else if(this.lookaheadRun(e,T)){this.enqueueToken(this.createToken(13,t,this._pos));this.pushStates(this.markSendTokens,this.stateScanTrivia)}else{this._pos=t;this.pushState(this.stateScanTrivia)}}stateScanTrivia(){var t=this._pos,e=this.readChar();if(h(e)){this.enqueueTrivia(t);this.enqueueToken(this.createToken(18,t,t));this.pushStates(this.markSendTokens,this.stop)}else if(this.lookaheadRun(e,this._isInTagAttributes?o:c))this.pushState(this.stateScanTrivia);else{this._pos=t;this.enqueueTrivia(t);this.pushState(this.markSendTokens)}}lookaheadRun(t,e,s=e){if(e(t)){for(var a=this._pos;s(this.readChar());)a=this._pos;this._pos=a;return!0}return!1}lookahead(t,e,s={}){for(var a=this._pos,i=0;i<e.length;i++){if(s.ignoreCase?d(t)!==d(e[i]):t!==e[i]){this._pos=a;return!1}i<e.length-1&&(t=this.readChar())}if(s.rest){var n=this._pos;if(!s.rest(this.readChar())){this._pos=a;return!1}this._pos=n}return!0}lookaheadOpenProcessingInstruction(t){return 63===t&&this.lookaheadRun(this.readChar(),r,u)}lookaheadCloseProcessingInstruction(t){return this.lookahead(t,[63,62])}lookaheadOpenCharacterData(t){return this.lookahead(t,[91,67,68,65,84,65,91],{ignoreCase:!0})}lookaheadCloseCharacterData(t){return this.lookahead(t,[93,93,62])}lookaheadMinusMinus(t){return this.lookahead(t,[45,45])}lookaheadOpenComment(t){return this.lookahead(t,[60,33,45,45])}lookaheadCloseComment(t){return this.lookahead(t,[45,45,62])}lookaheadDocumentType(t){return this.lookahead(t,[68,79,67,84,89,80,69],{ignoreCase:!0,rest:k})}lookaheadScript(t){return this.lookahead(t,[83,67,82,73,80,84],{ignoreCase:!0,rest:k})}lookaheadStyle(t){return this.lookahead(t,[83,84,89,76,69],{ignoreCase:!0,rest:k})}lookaheadTitle(t){return this.lookahead(t,[84,73,84,76,69],{ignoreCase:!0,rest:k})}lookaheadTextarea(t){return this.lookahead(t,[84,69,88,84,65,82,69,65],{ignoreCase:!0,rest:k})}lookaheadOpenStartTag(t,e){return 60===t&&e(this.readChar())}lookaheadOpenEndTag(t,e){return this.lookahead(t,[60,47])&&e(this.readChar())}lookaheadCloseStartOrEndTag(t){return 62===t||this.lookahead(t,[47,62])}lookaheadZeroWidth(t){var e=this._pos,s=t(this.readChar());this._pos=e;return s}createToken(t,e,s){var a=Object.create?Object.create(null):{};a.kind=t;a.pos=e;a.end=s;return a}}e.HtmlTokenizer=s;var a=/^(area|b(ase|r)|col|embed|hr|i(mg|nput)|keygen|link|meta|param|source|track|wbr)$/i,i=/^(a(bbr|udio|rea)?|b(d[io]|r|utton)?|c(ite|ode)|d(ata|el|fn)|em(bed)?|i(mg|n(put|s))|label|k(bd|eygen)|m(a(p|rk|th)|eter)|o(utput)|progress|q|ruby|s(amp|elect|mall|pan|trong|u[bp]|vg)?|time|u|var|wbr|#text)$/i,n=Object.create?Object.create(null):{};function h(t){return isNaN(t)}function o(t){return 47===t||c(t)}function r(t){return t>=97&&t<=122||t>=65&&t<=90||t>=48&&t<=57}e.isTagNameStartChar=r;function u(t){return isFinite(t)&&!c(t)&&62!==t}e.isTagNameChar=u;function k(t){return!u(t)}e.isNonTagNameChar=k;function S(t){return isFinite(t)&&!c(t)&&61!==t&&62!==t&&47!==t}e.isAttributeNameChar=S;function T(t){return isFinite(t)&&!c(t)&&62!==t}e.isUnquotedAttributeValueChar=T;function c(t){return 32===t||9===t||12===t||13===t||10===t}e.isWhitespaceChar=c;function p(t){return a.test(t)}e.isVoidTag=p;function l(t){return i.test(t)}e.isPhrasingContent=l;function d(t){return t>=97&&t<=122?t-32:t<128?t:t in n?n[t]:n[t]=String.fromCharCode(t).toUpperCase().charCodeAt(0)}e.toUpperChar=d;function C(t,e,s){var a=s&&"number"==typeof s.pos?s.pos:0,i=s&&"number"==typeof s.len?s.len:t.length-a,n=s&&s.ignoreCase,h=0;function o(){return h<i?t.charCodeAt(a+h++):NaN}for(var r=o(),u=0;u<e.length;u++){if(n?d(r)!==d(e[u]):r!==e[u])return!1;u<e.length-1&&(r=o())}return!0}e.lookahead=C}(t.Html||(t.Html={}))}(t.FormatService||(t.FormatService={}))}(Common||(Common={}));