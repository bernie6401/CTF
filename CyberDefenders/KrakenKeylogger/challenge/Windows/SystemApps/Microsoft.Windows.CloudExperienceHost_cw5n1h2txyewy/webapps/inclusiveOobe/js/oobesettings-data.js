﻿//
// Copyright (C) Microsoft. All rights reserved.
//
define(["lib/knockout", 'legacy/bridge', 'legacy/events', 'legacy/core', 'jsCommon/knockout-helpers'], (ko, bridge, constants, core, KoHelpers) => {
    class OobeSettingsData {
        // Takes in a list of settings and commits them, then logs associated telemetry and completes the webapp
        commitSettings(settings, privacyConsentPresentationVersion) {
            try {
                // Show the progress ring while committing async.
                bridge.fireEvent(CloudExperienceHost.Events.showProgressWhenPageIsBusy);

                CloudExperienceHostAPI.OobeSettingsManagerStaticsCore.commitSettingsAsync(settings, privacyConsentPresentationVersion).done(function () {
                    for (let setting of settings) {
                        bridge.invoke("CloudExperienceHost.Telemetry.logEvent", setting.canonicalName, setting.value);
                    }
                    bridge.fireEvent(constants.Events.done, constants.AppResult.success);
                },
                    function (err) {
                        bridge.invoke("CloudExperienceHost.Telemetry.logEvent", "CommitSettingsAsyncWorkerFailure", core.GetJsonFromError(err));
                        bridge.fireEvent(constants.Events.done, constants.AppResult.error);
                    });
            }
            catch (err) {
                bridge.invoke("CloudExperienceHost.Telemetry.logEvent", "CommitSettingsFailure", core.GetJsonFromError(err));
                bridge.fireEvent(constants.Events.done, constants.AppResult.error);
            }
        }

        initializeLearnMoreContentAsync() {
            return CloudExperienceHostAPI.OobeSettingsManagerStaticsCore.getLearnMorePlainTextAsync().then((result) => {
                if (CloudExperienceHostAPI.FeatureStaging.isOobeFeatureEnabled("OobePrivacySettingsHtmlLearnMore")) {
                    this.learnMoreContent = result;
                }
                else {
                    let msHtmlStringBody = result.replace(/\r/g, "</p><p>");
                    let msHtmlString = "<html><head><link href=\"/webapps/inclusiveOobe/css/inclusive-mseula.css\" rel=\"stylesheet\"></head><body><p>" + msHtmlStringBody + "</p></body></html>";
                    this.learnMoreContent = msHtmlString;
                }
            });
        }

        getLearnMoreContent() {
            return this.learnMoreContent;
        }

        updateLearnMoreContentForRender(doc, dirVal, isInternetAvailable, errorMessage, targetPersonality) {
            let cssOverride = (targetPersonality === CloudExperienceHost.TargetPersonality.InclusiveBlue) ? "/webapps/inclusiveOobe/css/inclusive-mseula.css" : "";
            if (cssOverride && (cssOverride !== "") && CloudExperienceHostAPI.FeatureStaging.isOobeFeatureEnabled("OobePrivacySettingsHtmlLearnMore")) {
                let fileRef = doc.head.ownerDocument.createElement("link");
                fileRef.setAttribute("rel", "stylesheet");
                fileRef.setAttribute("href", cssOverride);
                doc.head.appendChild(fileRef);
            }

            let privacyLinks = doc.querySelectorAll("a");
            for (let i = 0; i < privacyLinks.length; i++) {
                let link = privacyLinks[i];
                link.onclick = (e) => {
                    if (isInternetAvailable) {
                        // Styling on the local resource html content is managed by applying cssOverride, but the deep-linked server-side Privacy content
                        // is statically hosted with its own styles. It is TargetPersonality.InclusiveBlue by default (the initial existing personality)
                        // and supports other personalities via QueryString "profile" argument.
                        // Profile values must match the server-side value set.
                        let personalityQSParam = (targetPersonality === CloudExperienceHost.TargetPersonality.LiteWhite) ? "&profile=transparentLight" : "";
                        let url = e.target.href + personalityQSParam;
                        WinJS.xhr({ url: url }).then((response) => {
                            doc.location.href = url;
                        }, (error) => {
                            let html = "<html><head>";
                            if (cssOverride && (cssOverride !== "")) {
                                html = html + "<link href=\"" + cssOverride + "\" rel=\"stylesheet\">";
                            }
                            html = html + "</head><body><p>" + errorMessage + "</p></body></html>";
                            KoHelpers.loadIframeContent(doc, { content: html, dir: dirVal });
                        });
                        e.preventDefault();
                    }
                    else {
                        let innerHTML = "<html><head>";
                        if (cssOverride && (cssOverride !== "")) {
                            innerHTML = innerHTML + "<link href=\"" + cssOverride + "\" rel=\"stylesheet\">";
                        }
                        innerHTML = innerHTML + "</head><body><p>" + errorMessage + "</p></body></html>";
                        doc.body.innerHTML = innerHTML;
                        e.preventDefault();
                    }
                };
            }
        }

        getCssOverride(targetPersonality) {
            if (targetPersonality === CloudExperienceHost.TargetPersonality.InclusiveBlue) {
                return "/webapps/inclusiveOobe/css/inclusive-mseula.css";
            }
            return "";
        }

        showLearnMoreContent(doc, href, dirVal, isInternetAvailable, errorMessage, targetPersonality) {
            let cssOverride = this.getCssOverride(targetPersonality);

            if (isInternetAvailable) {
                let url = href;
                WinJS.xhr({ url: url }).then((response) => {
                    doc.location.href = url;
                    doc.body.focus();
                }, (error) => {
                    let html = "<html><head>";
                    if (cssOverride && (cssOverride !== "")) {
                        html = html + "<link href=\"" + cssOverride + "\" rel=\"stylesheet\">";
                    }
                    html = html + "</head><body><p>" + errorMessage + "</p></body></html>";
                    KoHelpers.loadIframeContent(doc, { content: html, dir: dirVal });
                });
            }
            else {
                let innerHTML = "<html><head>";
                if (cssOverride && (cssOverride !== "")) {
                    innerHTML = innerHTML + "<link href=\"" + cssOverride + "\" rel=\"stylesheet\">";
                }
                innerHTML = innerHTML + "</head><body><p>" + errorMessage + "</p></body></html>";
                doc.body.innerHTML = innerHTML;
            }
        }
    }
    return new OobeSettingsData();
});
