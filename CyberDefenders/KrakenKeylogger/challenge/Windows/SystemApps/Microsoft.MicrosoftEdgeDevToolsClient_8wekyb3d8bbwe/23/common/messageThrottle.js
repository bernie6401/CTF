﻿var Common;!function(e){"use strict";class s{constructor(){this._packetCount=0;this._data=""}static splitMessage(e){for(var t=e.length,a=Math.max(1,Math.ceil(t/s.MAX_MESSAGE_LENGTH)),n=[],r=0;r<a;r++){var i=r*s.MAX_MESSAGE_LENGTH,h=i+Math.min(s.MAX_MESSAGE_LENGTH,t-i),o={n:a,data:e.slice(i,h)};n.push(JSON.stringify(o))}return n}combineMessages(e){var s=JSON.parse(e.data);if(s.n>=1){this._data+=s.data||"";this._packetCount++;if(this._packetCount===s.n){var t=this._data;this._packetCount=0;this._data="";e.data=t;e.handled=!1}else e.handled=!0}else e.handled=!0}}s.MAX_MESSAGE_LENGTH=32768;e.MessageThrottle=s;class t extends s{constructor(e){super();this._messageHandlers=[];this._port=e}get name(){return this._port.name}initialize(){this._port.addEventListener("message",this.onmessage.bind(this))}postMessage(e){var t,a,n=s.splitMessage(e);for(t=0,a=n.length;t<a;t++){var r=n[t];this._port.postMessage(r)}return!0}addEventListener(e,s){if("message"!==e)throw new Error("Invalid event type");this._messageHandlers.push(s)}removeEventListener(e,s){if("message"!==e)throw new Error("Invalid event type");for(;;){var t=this._messageHandlers.indexOf(s);if(-1===t)break;this._messageHandlers.splice(t,1)}}onmessage(e){this.combineMessages(e);if(!e.handled){var s,t;for(s=0,t=this._messageHandlers.length;s<t;s++){(0,this._messageHandlers[s])(e)}}}}e.PortThrottler=t}(Common||(Common={}));
