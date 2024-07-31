function renderResult(arr) {
    const str = arr.map((item) => {
        return `<tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                    <th scope="row"
                        class="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                        ${item.name}
                    </th>
                    <th scope="row"
                        class="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                        ${item.status ? "Successful ✅" : "Failed ❌"} ${item.message ?? ""}
                    </th>
                </tr>`
    }).join('');
    document.querySelector('.response-table').innerHTML = str;
}

const result = []

async function test() {

    /* CDP Detection https://datadome.co/threat-research/how-new-headless-chrome-the-cdp-signal-are-impacting-bot-detection/ */

    try {
        var detected = false;
        var e = new Error();
        Object.defineProperty(e, 'stack', {
            get() {
                detected = true;
            }
        });
        console.log(e);
        if (detected === true) result.push({ name: 'CDP Detection', status: false })
        else result.push({ name: 'CDP Detection', status: true })
    } catch (e) {
        result.push({ name: 'CDP Detection', status: false, message: e.message })
    }


    /* Detect puppeteer-extra-plugin-stealth https://datadome.co/threat-research/how-datadome-detects-puppeteer-extra-stealth/ */
    try {
        let iframe = document.createElement('iframe');
        iframe.classList.add('hidden');
        iframe.srcdoc = 'test';
        document.body.appendChild(iframe);

        let detected = iframe.contentWindow.self.get?.toString();
        if (detected && String(detected).includes(":)")) result.push({ name: 'puppeteer-extra-plugin-stealth - Test 1', status: false })
        else result.push({ name: 'puppeteer-extra-plugin-stealth - Test 1', status: true })
    } catch (e) {
        result.push({ name: 'puppeteer-extra-plugin-stealth - Test 1', status: false, message: e.message })
    }


    /* User agent headless test */

    try {
        if (navigator.userAgent.toLowerCase().includes('headless')) result.push({ name: 'User agent headless test', status: false })
        else result.push({ name: 'User agent headless test', status: true })
    } catch (e) {
        result.push({ name: 'User agent headless test', status: false, message: e.message })
    }

    /* Navigator webdriver test */
    try {
        navigator.webdriver ? (result.push({ name: 'Navigator webdriver test', status: false })) : (result.push({ name: 'Navigator webdriver test', status: true }))
    } catch (e) {
        result.push({ name: 'Navigator webdriver test', status: false, message: e.message })
    }

    /* Testing some properties added to document and window objects */

    try {
        if (runBotDetection()) result.push({ name: 'Testing some properties added to document and window objects', status: false })
        else result.push({ name: 'Testing some properties added to document and window objects', status: true })
    } catch (e) {
        result.push({ name: 'Testing some properties added to document and window objects', status: false, message: e.message })
    }


    /* navigator.plugins Test */

    try {
        if (navigator.plugins.length === 0) result.push({ name: 'navigator.plugins Test', status: false })
        else result.push({ name: 'navigator.plugins Test', status: true })
    } catch (e) {
        result.push({ name: 'navigator.plugins Test', status: false, message: e.message })
    }

    /* window.chrome */

    try {
        if ((window.chrome?.csi()?.onloadT ?? false) && (window.chrome?.app?.InstallState ?? false)) result.push({ name: 'window.chrome Test', status: false })
        else result.push({ name: 'window.chrome Test', status: true })
    } catch (e) {
        result.push({ name: 'window.chrome Test', status: false, message: e.message })
    }


    /* Webgl renderer test */
    try {
        const webglRenderer = getUnmaskedRenderer()
        if (!webglRenderer || String(webglRenderer).toLowerCase().includes("swiftshader") || String(webglRenderer).includes("Mesa OffScreen")) result.push({ name: 'Webgl renderer test', status: false })
        else result.push({ name: 'Webgl renderer test', status: true })
    } catch (e) {
        result.push({ name: 'Webgl renderer test', status: false, message: e.message })
    }

    /* WebRTC Support */

    try {
        if (checkWebRTCSupport()) result.push({ name: 'WebRTC Support', status: true })
        else result.push({ name: 'WebRTC Support', status: false })
    } catch (e) {
        result.push({ name: 'WebRTC Support', status: false, message: e.message })
    }

    /* navigator.languages Test http://antoinevastel.com/bot%20detection/2017/08/05/detect-chrome-headless.html */
    try {
        if (navigator.languages == "" || navigator.languages.length == 0) result.push({ name: 'navigator.languages Test', status: false })
        else result.push({ name: 'navigator.languages Test', status: true })
    } catch (e) {
        result.push({ name: 'navigator.languages Test', status: false, message: e.message })
    }

    /* Webgl vendor Test http://antoinevastel.com/bot%20detection/2017/08/05/detect-chrome-headless.html */
    try {
        const webglVendorData = webglVendor()
        if (webglVendorData == "Brian Paul") result.push({ name: 'Webgl vendor Test', status: false })
        else result.push({ name: 'Webgl vendor Test', status: true })
    } catch (e) {
        result.push({ name: 'Webgl vendor Test', status: false, message: e.message })
    }


    /* Missing image Test */
    try {
        if (imageTest()) result.push({ name: 'Missing image Test', status: false })
        else result.push({ name: 'Missing image Test', status: true })
    } catch (e) {
        result.push({ name: 'Missing image Test', status: false, message: e.message })
    }

    /* window.screen.availHeight Test */


    try {
        if (window.screen.height == window.screen.availHeight) result.push({ name: 'window.screen.availHeight Test', status: false })
        else result.push({ name: 'window.screen.availHeight Test', status: true })
    } catch (e) {
        result.push({ name: 'window.screen.availHeight Test', status: false, message: e.message })
    }


    /* Devtools Detector Test */
    try {
        var devtoolsStatus = false
        var view = document.createElement('div');
        document.body.appendChild(view);

        devtoolsDetector.addListener(function (isOpen) {
            devtoolsStatus = isOpen

        });
        devtoolsDetector.launch();
        await new Promise(resolve => setTimeout(resolve, 1))
        if (devtoolsStatus == true) result.push({ name: 'Devtools Detector Test', status: false })
        else result.push({ name: 'Devtools Detector Test', status: true })
        renderResult(result)
    } catch (e) {
        result.push({ name: 'Devtools Detector Test', status: false, message: e.message })
    }


        





















}

function imageTest() {
    var testHeadless = false
    var body = document.getElementsByTagName("body")[0];
    var image = document.createElement("img");
    image.src = "http://iloveponeydotcom32188.jg";
    image.setAttribute("id", "fakeimage");
    image.classList.add("hidden")
    body.appendChild(image);
    image.onerror = function () {
        if (image.width == 0 && image.height == 0) {
            testHeadless = true
        }
    }
    return testHeadless
}

function getUnmaskedRenderer() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

    if (!gl) return false

    const extension = gl.getExtension('WEBGL_debug_renderer_info');

    if (!extension) return false

    return gl.getParameter(extension.UNMASKED_RENDERER_WEBGL);
}


function webglVendor() {
    var canvas = document.createElement('canvas');
    var gl = canvas.getContext('webgl');
    var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
    return vendor
}


function checkWebRTCSupport() {
    if (navigator.mediaDevices &&
        navigator.mediaDevices.getUserMedia &&
        window.RTCPeerConnection) {
        return true;
    } else {
        return false;
    }
}

/* https://stackoverflow.com/a/41220267/26471560 */
runBotDetection = function () {
    var documentDetectionKeys = [
        "__webdriver_evaluate",
        "__selenium_evaluate",
        "__webdriver_script_function",
        "__webdriver_script_func",
        "__webdriver_script_fn",
        "__fxdriver_evaluate",
        "__driver_unwrapped",
        "__webdriver_unwrapped",
        "__driver_evaluate",
        "__selenium_unwrapped",
        "__fxdriver_unwrapped",
    ];

    var windowDetectionKeys = [
        "_phantom",
        "__nightmare",
        "_selenium",
        "callPhantom",
        "callSelenium",
        "_Selenium_IDE_Recorder",
    ];

    for (const windowDetectionKey in windowDetectionKeys) {
        const windowDetectionKeyValue = windowDetectionKeys[windowDetectionKey];
        if (window[windowDetectionKeyValue]) {
            return true;
        }
    };
    for (const documentDetectionKey in documentDetectionKeys) {
        const documentDetectionKeyValue = documentDetectionKeys[documentDetectionKey];
        if (window['document'][documentDetectionKeyValue]) {
            return true;
        }
    };

    for (const documentKey in window['document']) {
        if (documentKey.match(/\$[a-z]dc_/) && window['document'][documentKey]['cache_']) {
            return true;
        }
    }

    if (window['external'] && window['external'].toString() && (window['external'].toString()['indexOf']('Sequentum') != -1)) return true;

    if (window['document']['documentElement']['getAttribute']('selenium')) return true;
    if (window['document']['documentElement']['getAttribute']('webdriver')) return true;
    if (window['document']['documentElement']['getAttribute']('driver')) return true;

    return false;
};


test()