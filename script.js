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
        if (navigator.plugins == "") result.push({ name: 'navigator.plugins Test', status: false })
        else result.push({ name: 'navigator.plugins Test', status: true })
    } catch (e) {
        result.push({ name: 'navigator.plugins Test', status: false, message: e.message })
    }

    /* window.chrome */

    try {
        if (detectBrowser() == 'Chrome' && window.chrome) result.push({ name: 'window.chrome Test', status: true })
        else result.push({ name: 'window.chrome Test', status: false })
    } catch (e) {
        confirm(e.message)
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
        if (navigator.languages == "") result.push({ name: 'navigator.languages Test', status: false })
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
        if (isMobileTablet() == false && window.screen?.height && (window.screen.height == window.screen.availHeight)) result.push({ name: 'window.screen.availHeight Test', status: false })
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
    } catch (e) {
        result.push({ name: 'Devtools Detector Test', status: false, message: e.message })
    }






    renderResult(result)
}


function isMobileTablet() {
    var check = false;
    (function (a) {
        if (/(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows ce|xda|xiino|android|ipad|playbook|silk/i.test(a) || /1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i.test(a.substr(0, 4)))
            check = true;
    })(navigator.userAgent || navigator.vendor || window.opera);
    return check;
}

function detectBrowser() {
    if ((navigator.userAgent.indexOf("Opera") || navigator.userAgent.indexOf('OPR')) != -1) {
        return 'Opera';
    } else if (navigator.userAgent.indexOf("Edg") != -1) {
        return 'Edge';
    } else if (navigator.userAgent.indexOf("Chrome") != -1) {
        return 'Chrome';
    } else if (navigator.userAgent.indexOf("Safari") != -1) {
        return 'Safari';
    } else if (navigator.userAgent.indexOf("Firefox") != -1) {
        return 'Firefox';
    } else if ((navigator.userAgent.indexOf("MSIE") != -1) || (!!document.documentMode == true)) //IF IE > 10
    {
        return 'IE';
    } else {
        return 'unknown';
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