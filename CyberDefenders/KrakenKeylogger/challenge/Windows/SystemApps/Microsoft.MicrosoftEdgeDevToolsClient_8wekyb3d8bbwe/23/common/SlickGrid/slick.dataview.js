﻿(function(n){function t(t){function fi(){ot=!0}function ei(){ot=!1;e()}function oi(n){f=n}function si(n){rt=n}function d(n){var i,t,u;for(n=n||0,t=n,u=r.length;t<u;t++){if(i=r[t][c],i===undefined)throw"Each data element must implement a unique 'id' property";s[i]=t}}function hi(){for(var t,n=0,i=r.length;n<i;n++)if(t=r[n][c],t===undefined||s[t]!==n)throw"Each data element must implement a unique 'id' property"}function ci(){return r}function li(n,t){t!==undefined&&(c=t);r=h=n;s={};d();hi();e()}function ai(n){n.pageSize!=undefined&&(u=n.pageSize,l=u?Math.min(l,Math.max(0,Math.ceil(a/u)-1)):0);n.pageNum!=undefined&&(l=Math.min(n.pageNum,Math.max(0,Math.ceil(a/u)-1)));ht.notify(ct(),null,g);e()}function ct(){var n=u?Math.max(1,Math.ceil(a/u)):1;return{pageSize:u,pageNum:l,totalRows:a,totalPages:n}}function kt(n,t){nt=t;it=n;tt=null;t===!1&&r.reverse();r.sort(n);t===!1&&r.reverse();s={};d();e()}function dt(n,t){nt=t;tt=n;it=null;var i=Object.prototype.toString;Object.prototype.toString=typeof n=="function"?n:function(){return this[n]};t===!1&&r.reverse();r.sort();Object.prototype.toString=i;t===!1&&r.reverse();s={};d();e()}function vi(){it?kt(it,nt):tt&&dt(tt,nt)}function yi(n){v=n;t.inlineFilters&&(vt=br(),yt=kr());e()}function pi(){return i}function ut(r){var f,u,o;for(t.groupItemMetadataProvider||(t.groupItemMetadataProvider=new Slick.Data.GroupItemMetadataProvider),w=[],k=[],r=r||[],i=r instanceof Array?r:[r],f=0;f<i.length;f++){for(u=i[f]=n.extend(!0,{},ui,i[f]),u.getterIsAFn=typeof u.getter=="function",u.compiledAccumulators=[],o=u.aggregators.length;o--;)u.compiledAccumulators[o]=wr(u.aggregators[o]);k[f]={}}e()}function wi(n,t,i){if(n==null){ut([]);return}ut({getter:n,formatter:t,comparer:i})}function bi(n,t){if(!i.length)throw new Error("At least one grouping must be specified before calling setAggregators().");i[0].aggregators=n;i[0].aggregateCollapsed=t;ut(i)}function ki(n){return r[n]}function di(n){return s[n]}function lt(){if(!p){p={};for(var n=0,t=o.length;n<t;n++)p[o[n][c]]=n}}function gi(n){return lt(),p[n]}function nr(n){return r[s[n]]}function tr(n){var i=[],t,u,r;for(lt(),t=0,u=n.length;t<u;t++)r=p[n[t]],r!=null&&(i[i.length]=r);return i}function ir(n){for(var i=[],t=0,r=n.length;t<r;t++)n[t]<o.length&&(i[i.length]=o[n[t]][c]);return i}function rr(n,t){if(s[n]===undefined||n!==t[c])throw"Invalid or non-matching id";r[s[n]]=t;b||(b={});b[n]=!0;e()}function ur(n,t){r.splice(n,0,t);d(n);e()}function fr(n){r.push(n);d(r.length-1);e()}function er(n){var t=s[n];if(t===undefined)throw"Invalid id";delete s[n];r.splice(t,1);d(t);e()}function or(){return o.length}function sr(n){var t=o[n],r;return t&&t.__group&&t.totals&&!t.totals.initialized?(r=i[t.level],r.displayTotalsRow||(et(t.totals),t.title=r.formatter?r.formatter(t):t.value)):t&&t.__groupTotals&&!t.initialized&&et(t),t}function hr(n){var i=o[n];return i===undefined?null:i.__group?t.groupItemMetadataProvider.getGroupRowMetadata(i):i.__groupTotals?t.groupItemMetadataProvider.getTotalsRowMetadata(i):null}function gt(n,t){if(n==null)for(var r=0;r<i.length;r++)k[r]={},i[r].collapsed=t;else k[n]={},i[n].collapsed=t;e()}function cr(n){gt(n,!0)}function lr(n){gt(n,!1)}function ft(n,t,r){k[n][t]=i[n].collapsed^r;e()}function ar(){var n=Array.prototype.slice.call(arguments),t=n[0];n.length==1&&t.indexOf(y)!=-1?ft(t.split(y).length-1,t,!0):ft(n.length-1,n.join(y),!0)}function vr(){var n=Array.prototype.slice.call(arguments),t=n[0];n.length==1&&t.indexOf(y)!=-1?ft(t.split(y).length-1,t,!1):ft(n.length-1,n.join(y),!1)}function yr(){return w}function ni(n,t){for(var r,f,e=[],h={},c,o=t?t.level+1:0,s=i[o],u=0,l=s.predefinedValues.length;u<l;u++)f=s.predefinedValues[u],r=h[f],r||(r=new Slick.Group,r.value=f,r.level=o,r.groupingKey=(t?t.groupingKey+y:"")+f,e[e.length]=r,h[f]=r);for(u=0,l=n.length;u<l;u++)c=n[u],f=s.getterIsAFn?s.getter(c):c[s.getter],r=h[f],r||(r=new Slick.Group,r.value=f,r.level=o,r.groupingKey=(t?t.groupingKey+y:"")+f,e[e.length]=r,h[f]=r),r.rows[r.count++]=c;if(o<i.length-1)for(u=0;u<e.length;u++)r=e[u],r.groups=ni(r.rows,r);return e.sort(i[o].comparer),e}function et(n){var t=n.group,r=i[t.level],o=t.level==i.length,u,f=r.aggregators.length,e;if(!o&&r.aggregateChildGroups)for(e=t.groups.length;e--;)t.groups[e].initialized||et(t.groups[e]);while(f--)u=r.aggregators[f],u.init(),!o&&r.aggregateChildGroups?r.compiledAccumulators[f].call(u,t.groups):r.compiledAccumulators[f].call(u,t.rows),u.storeResult(n);n.initialized=!0}function pr(n){var r=i[n.level],t=new Slick.GroupTotals;t.group=n;n.totals=t;r.lazyTotalsCalculation||et(t)}function ti(n,t){t=t||0;for(var u=i[t],e=u.collapsed,o=k[t],f=n.length,r;f--;)(r=n[f],!r.collapsed||u.aggregateCollapsed)&&(r.groups&&ti(r.groups,t+1),u.aggregators.length&&(u.aggregateEmpty||r.rows.length||r.groups&&r.groups.length)&&pr(r),r.collapsed=e^o[r.groupingKey],r.title=u.formatter?u.formatter(r):r.value)}function ii(n,t){var f,c,e,l;t=t||0;var h=i[t],u=[],o,s=0,r;for(f=0,c=n.length;f<c;f++){if(r=n[f],u[s++]=r,!r.collapsed)for(o=r.groups?ii(r.groups,t+1):r.rows,e=0,l=o.length;e<l;e++)u[s++]=o[e];r.totals&&h.displayTotalsRow&&(!r.collapsed||h.aggregateCollapsed)&&(u[s++]=r.totals)}return u}function at(n){var t=n.toString().match(/^[^(]*\(([^)]*)\)\s*{([\s\S]*)}$/);return{params:t[1].split(","),body:t[2]}}function wr(n){var t=at(n.accumulate),i=new Function("_items","for (var "+t.params[0]+", _i=0, _il=_items.length; _i<_il; _i++) {"+t.params[0]+" = _items[_i]; "+t.body+"}");return i.displayName=i.name="compiledAccumulatorLoop",i}function br(){var i=at(v),r=i.body.replace(/return\s*(false|!1)\s*([;}]|$)/gi,"{ continue _coreloop; }$2").replace(/return\s*(true|!0)\s*([;}]|$)/gi,"{ _retval[_idx++] = $item$; continue _coreloop; }$2").replace(/return ([^;}]+?)\s*([;}]|$)/gi,"{ if ($1) { _retval[_idx++] = $item$; }; continue _coreloop; }$2"),n="var _retval = [], _idx = 0; var $item$, $args$ = _args; _coreloop: for (var _i = 0, _il = _items.length; _i < _il; _i++) { $item$ = _items[_i]; $filter$; } return _retval; ",t;return n=n.replace(/\$filter\$/gi,r),n=n.replace(/\$item\$/gi,i.params[0]),n=n.replace(/\$args\$/gi,i.params[1]),t=new Function("_items,_args",n),t.displayName=t.name="compiledFilter",t}function kr(){var i=at(v),r=i.body.replace(/return\s*(false|!1)\s*([;}]|$)/gi,"{ continue _coreloop; }$2").replace(/return\s*(true|!0)\s*([;}]|$)/gi,"{ _cache[_i] = true;_retval[_idx++] = $item$; continue _coreloop; }$2").replace(/return ([^;}]+?)\s*([;}]|$)/gi,"{ if ((_cache[_i] = $1)) { _retval[_idx++] = $item$; }; continue _coreloop; }$2"),n="var _retval = [], _idx = 0; var $item$, $args$ = _args; _coreloop: for (var _i = 0, _il = _items.length; _i < _il; _i++) { $item$ = _items[_i]; if (_cache[_i]) { _retval[_idx++] = $item$; continue _coreloop; } $filter$; } return _retval; ",t;return n=n.replace(/\$filter\$/gi,r),n=n.replace(/\$item\$/gi,i.params[0]),n=n.replace(/\$args\$/gi,i.params[1]),t=new Function("_items,_args,_cache",n),t.displayName=t.name="compiledFilterWithCaching",t}function dr(n,t){for(var r=[],u=0,i=0,f=n.length;i<f;i++)v(n[i],t)&&(r[u++]=n[i]);return r}function gr(n,t,i){for(var f=[],e=0,u,r=0,o=n.length;r<o;r++)u=n[r],i[r]?f[e++]=u:v(u,t)&&(f[e++]=u,i[r]=!0);return f}function nu(n){var i,e,r;return v?(i=t.inlineFilters?vt:dr,e=t.inlineFilters?yt:gr,f.isFilterNarrowing?h=i(h,rt):f.isFilterExpanding?h=e(n,rt,pt):f.isFilterUnchanged||(h=i(n,rt))):h=u?n:n.concat(),u?(h.length<l*u&&(l=Math.floor(h.length/u)),r=h.slice(u*l,u*l+u)):r=h,{totalRows:h.length,rows:r}}function tu(n,t){var r,e,s,o=[],h=0,l=t.length,u,a;for(f&&f.ignoreDiffsBefore&&(h=Math.max(0,Math.min(t.length,f.ignoreDiffsBefore))),f&&f.ignoreDiffsAfter&&(l=Math.min(t.length,Math.max(0,f.ignoreDiffsAfter))),u=h,a=n.length;u<l;u++)u>=a?o[o.length]=u:(r=t[u],e=n[u],(i.length&&(s=r.__nonDataRow||e.__nonDataRow)&&r.__group!==e.__group||r.__group&&!r.equals(e)||s&&(r.__groupTotals||e.__groupTotals)||r[c]!=e[c]||b&&b[r[c]])&&(o[o.length]=u));return o}function ri(n){var r,t,u;return p=null,(f.isFilterNarrowing!=st.isFilterNarrowing||f.isFilterExpanding!=st.isFilterExpanding)&&(pt=[]),r=nu(n),a=r.totalRows,t=r.rows,w=[],i.length&&(w=ni(t),w.length&&(ti(w),t=ii(w))),u=tu(o,t),o=t,u}function e(){if(!ot){var t=o.length,i=a,n=ri(r,v);u&&a<l*u&&(l=Math.max(0,Math.ceil(a/u)-1),n=ri(r,v));b=null;st=f;f={};i!=a&&ht.notify(ct(),null,g);t!=o.length&&wt.notify({previous:t,current:o.length},null,g);n.length>0&&bt.notify({rows:n},null,g)}}function iu(t,i,r){function o(n){f.join(",")!=n.join(",")&&(f=n,s.notify({grid:t,ids:f},new Slick.EventData,u))}function h(){if(f.length>0){e=!0;var n=u.mapIdsToRows(f);i||o(u.mapRowsToIds(n));t.setSelectedRows(n);e=!1}}var u=this,e,f=u.mapRowsToIds(t.getSelectedRows()),s=new Slick.Event;return t.onSelectedRowsChanged.subscribe(function(){var i,s;e||(i=u.mapRowsToIds(t.getSelectedRows()),r&&t.getOptions().multiSelect?(s=n.grep(f,function(n){return u.getRowById(n)===undefined}),o(s.concat(i))):o(i))}),this.onRowsChanged.subscribe(h),this.onRowCountChanged.subscribe(h),s}function ru(n,t){function u(n){var t,r;i={};for(t in n)r=o[t][c],i[r]=n[t]}function f(){var u,f,e;if(i){r=!0;lt();u={};for(f in i)e=p[f],e!=undefined&&(u[e]=i[f]);n.setCellCssStyles(t,u);r=!1}}var i,r;u(n.getCellCssStyles(t));n.onCellCssStylesChanged.subscribe(function(n,i){r||t==i.key&&i.hash&&u(i.hash)});this.onRowsChanged.subscribe(f);this.onRowCountChanged.subscribe(f)}var g=this,c="id",r=[],o=[],s={},p=null,v=null,b=null,ot=!1,nt=!0,tt,it,f={},st={},rt,h=[],vt,yt,pt=[],ui={getter:null,formatter:null,comparer:function(n,t){return n.value-t.value},predefinedValues:[],aggregators:[],aggregateEmpty:!1,aggregateCollapsed:!1,aggregateChildGroups:!1,collapsed:!1,displayTotalsRow:!0,lazyTotalsCalculation:!1},i=[],w=[],k=[],y=":|:",u=0,l=0,a=0,wt=new Slick.Event,bt=new Slick.Event,ht=new Slick.Event;t=n.extend(!0,{},{groupItemMetadataProvider:null,inlineFilters:!1},t);n.extend(this,{beginUpdate:fi,endUpdate:ei,setPagingOptions:ai,getPagingInfo:ct,getItems:ci,setItems:li,setFilter:yi,sort:kt,fastSort:dt,reSort:vi,setGrouping:ut,getGrouping:pi,groupBy:wi,setAggregators:bi,collapseAllGroups:cr,expandAllGroups:lr,collapseGroup:ar,expandGroup:vr,getGroups:yr,getIdxById:di,getRowById:gi,getItemById:nr,getItemByIdx:ki,mapRowsToIds:ir,mapIdsToRows:tr,setRefreshHints:oi,setFilterArgs:si,refresh:e,updateItem:rr,insertItem:ur,addItem:fr,deleteItem:er,syncGridSelection:iu,syncGridCellCssStyles:ru,getLength:or,getItem:sr,getItemMetadata:hr,onRowCountChanged:wt,onRowsChanged:bt,onPagingInfoChanged:ht})}function i(n){this.field_=n;this.init=function(){this.count_=0;this.nonNullCount_=0;this.sum_=0};this.accumulate=function(n){var t=n[this.field_];this.count_++;t!=null&&t!==""&&t!==NaN&&(this.nonNullCount_++,this.sum_+=parseFloat(t))};this.storeResult=function(n){n.avg||(n.avg={});this.nonNullCount_!=0&&(n.avg[this.field_]=this.sum_/this.nonNullCount_)}}function r(n){this.field_=n;this.init=function(){this.min_=null};this.accumulate=function(n){var t=n[this.field_];t!=null&&t!==""&&t!==NaN&&(this.min_==null||t<this.min_)&&(this.min_=t)};this.storeResult=function(n){n.min||(n.min={});n.min[this.field_]=this.min_}}function u(n){this.field_=n;this.init=function(){this.max_=null};this.accumulate=function(n){var t=n[this.field_];t!=null&&t!==""&&t!==NaN&&(this.max_==null||t>this.max_)&&(this.max_=t)};this.storeResult=function(n){n.max||(n.max={});n.max[this.field_]=this.max_}}function f(n){this.field_=n;this.init=function(){this.sum_=null};this.accumulate=function(n){var t=n[this.field_];t!=null&&t!==""&&t!==NaN&&(this.sum_+=parseFloat(t))};this.storeResult=function(n){n.sum||(n.sum={});n.sum[this.field_]=this.sum_}}n.extend(!0,window,{Slick:{Data:{DataView:t,Aggregators:{Avg:i,Min:r,Max:u,Sum:f}}}})})(jQuery)
//# sourceMappingURL=slick.dataview.min.js.map