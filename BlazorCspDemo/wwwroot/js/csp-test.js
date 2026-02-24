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
