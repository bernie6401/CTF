﻿!function(e){function t(t){for(var n,r,l=t[0],a=t[1],d=t[2],u=0,p=[];u<l.length;u++){r=l[u];s[r]&&p.push(s[r][0]);s[r]=0}for(n in a)Object.prototype.hasOwnProperty.call(a,n)&&(e[n]=a[n]);c&&c(t);for(;p.length;)p.shift()();i.push.apply(i,d||[]);return o()}function o(){for(var e,t=0;t<i.length;t++){for(var o=i[t],n=!0,l=1;l<o.length;l++){var a=o[l];0!==s[a]&&(n=!1)}if(n){i.splice(t--,1);e=r(r.s=o[0])}}return e}var n={},s={8:0},i=[];function r(t){if(n[t])return n[t].exports;var o=n[t]={i:t,l:!1,exports:{}};e[t].call(o.exports,o,o.exports,r);o.l=!0;return o.exports}r.m=e;r.c=n;r.d=function(e,t,o){r.o(e,t)||Object.defineProperty(e,t,{configurable:!1,enumerable:!0,get:o})};r.r=function(e){Object.defineProperty(e,"__esModule",{value:!0})};r.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};r.d(t,"a",t);return t};r.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)};r.p="";var l=window.webpackJsonp=window.webpackJsonp||[],a=l.push.bind(l);l.push=t;l=l.slice();for(var d=0;d<l.length;d++)t(l[d]);var c=a;i.push([209,4]);o()}({209:function(e,t,o){"use strict";o.r(t);var n=o(70),s=o(11),i=o(13),r=o(10),l=o(6),a=o(59);function d(e){const t=Object(r.g)();if(""!==e.style){const t=Array.from(document.head.querySelectorAll("style, link[type='text/css']"));for(const e of t)"pluginPopupWindowDefault"!==e.id&&document.head.removeChild(e);document.head.innerHTML+=e.style}const o=document.getElementById(e.isTooltip?"contextmenu":"plugin-vs-tooltip");o&&(o.style.display="none");const n=document.getElementById(e.isTooltip?"plugin-vs-tooltip":"contextmenu");if(n){if(e.isTooltip)n.outerHTML=e.content;else{const o=JSON.parse(e.content);o.ariaLabel&&o.ariaLabel.length>0&&n.setAttribute("aria-label",o.ariaLabel);Object(s.initializeForPopup)(o);if("headerOverflowMenu"===o.id){t.call("ms:header","OverflowPopupShown",[]);n.classList.add("headerMenu");document.body.classList.add("headerMenuVisible");p(n);const e=document.createElement("div");e.classList.add("partialTopBorder");n.insertBefore(e,n.firstChild)}else if("emulationContextMenu"===o.id){t.call("ms:header","EmulationPopupShown",[]);n.classList.add("headerMenu");document.body.classList.add("headerMenuVisible");const e=document.createElement("div");e.classList.add("partialTopBorder");e.classList.add("docModeButtonTopBorder");n.insertBefore(e,n.firstChild)}else{n.classList.remove("headerMenu");document.body.classList.remove("headerMenuVisible")}}c(e.x,e.y,e.width,e.height)}return!0}function c(e,t,o,n){const s=parent.document.getElementById("popup");s.style.left=e+"px";s.style.top=t+"px";s.style.width=o+"px";s.style.height=n+"px";s.style.position="absolute";s.style.display="block";s.style.visibility="visible";s.style.zIndex="100"}function u(){const e=parent.document.getElementById("popup");e.removeAttribute("style");e.style.visibility="hidden";e.style.display="none";Object(r.g)().call("ms:header","PopupHidden",[]);return!0}function p(e){const t=e.querySelectorAll(".menuitem");for(const e of t)for(const t of e.classList){const o=t.match(/badgeCount_(\d+)$/);if(o&&o[1]){t.add("badgeType2");99===parseInt(o[1],10)?e.querySelector(".shortcut").textContent="99+":e.querySelector(".shortcut").textContent=o[1]}}}window.addEventListener("DOMContentLoaded",()=>{const e=Object(r.g)();window.addEventListener("load",async()=>{await Object(n.a)();e.register("showPopup",async e=>d(e));e.register("hidePopup",async()=>u());window.setImmediate(()=>{Object(i.A)(l.c.popup);e.call("ms:host","postPendingMessageToPlugin",[l.c.popup]);a.markToolReady(l.c.popup)})})})}});
