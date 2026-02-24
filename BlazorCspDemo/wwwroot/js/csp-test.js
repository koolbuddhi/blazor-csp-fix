// csp-test.js — External JS for CSP demo purposes

/**
 * Safe DOM manipulation function.
 * Works in both Insecure and Secure modes because it is loaded
 * from an external file (covered by 'self' in script-src).
 */
function changeTextColor(elementId, color) {
    var el = document.getElementById(elementId);
    if (el) {
        el.style.color = color;
        return true;
    }
    return false;
}

/**
 * Attempts to use eval() — blocked in Secure mode
 * because eval() requires 'unsafe-eval' in script-src.
 */
function tryEval() {
    try {
        var result = eval('2 + 2');
        return { success: true, result: result, message: 'eval() executed successfully. Result: ' + result };
    } catch (e) {
        return { success: false, result: null, message: 'eval() BLOCKED by CSP: ' + e.message };
    }
}

/**
 * Attempts to create and execute an inline script dynamically.
 * Blocked in Secure mode — the injected script lacks a valid nonce.
 */
function tryDynamicScript() {
    try {
        var script = document.createElement('script');
        script.textContent = 'document.getElementById("dynamic-script-result").textContent = "Dynamic script executed!";';
        document.body.appendChild(script);
        return { success: true, message: 'Dynamic script injection attempted.' };
    } catch (e) {
        return { success: false, message: 'Dynamic script BLOCKED: ' + e.message };
    }
}

/**
 * Reads text content of an element by ID.
 */
function getElementText(elementId) {
    var el = document.getElementById(elementId);
    return el ? el.textContent : '';
}

/**
 * Counter increment via JS interop — demonstrates JS interop under CSP.
 */
function incrementCounterJs(currentValue) {
    return currentValue + 1;
}

/**
 * Checks if the nonced inline script in App.razor executed.
 */
function checkNoncedScript() {
    return window.__cspNoncePresent === true;
}

/**
 * Uploads a file via fetch — used by UploadDemo.razor to POST files
 * to the upload API endpoints without antiforgery token issues.
 */
function uploadFileViaFetch(url, fileName, contentType, base64Data) {
    var byteCharacters = atob(base64Data);
    var byteNumbers = new Array(byteCharacters.length);
    for (var i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    var byteArray = new Uint8Array(byteNumbers);
    var blob = new Blob([byteArray], { type: contentType });

    var formData = new FormData();
    formData.append('file', blob, fileName);

    return fetch(url, { method: 'POST', body: formData })
        .then(function (resp) { return resp.json(); });
}

/**
 * Simulates a CSP bypass attack using 'self' + user-uploaded files.
 * Uploads a crafted .js file to the insecure endpoint, then loads it
 * as a <script> tag. Since the file is served from 'self', CSP allows it
 * even in Secure (nonce-based) mode.
 */
function simulateUploadAttack(uploadUrl, scriptPath) {
    var payload = 'window.__cspBypassProof = true; '
        + 'document.getElementById("attack-result").textContent = '
        + '"SCRIPT EXECUTED \\u2014 CSP bypassed via self + uploaded file";';

    var blob = new Blob([payload], { type: 'application/javascript' });
    var formData = new FormData();
    formData.append('file', blob, 'attack-demo.js');

    return fetch(uploadUrl, { method: 'POST', body: formData })
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
            // Load the uploaded file as a script
            var script = document.createElement('script');
            script.src = data.url; // e.g., /uploads/attack-demo.js
            document.body.appendChild(script);

            // Check if it executed after a short delay
            return new Promise(function (resolve) {
                setTimeout(function () {
                    resolve(window.__cspBypassProof === true);
                }, 500);
            });
        });
}

/**
 * NavMenu mobile toggle — replaces the inline onclick handler
 * that violates CSP. Attached via addEventListener from external JS.
 */
document.addEventListener('DOMContentLoaded', function () {
    var navScrollable = document.querySelector('.nav-scrollable');
    if (navScrollable) {
        navScrollable.addEventListener('click', function () {
            var toggler = document.querySelector('.navbar-toggler');
            if (toggler) {
                toggler.click();
            }
        });
    }
});
