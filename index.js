const puppeteer = require('puppeteer-extra')

const StealthPlugin = require('puppeteer-extra-plugin-stealth')
puppeteer.use(StealthPlugin())


puppeteer.launch({
    headless: false,
    args: ['--no-sandbox', '--disable-setuid-sandbox', "--disable-blink-features=AutomationControlled", '--disable-infobars']
}).then(async browser => {
    const page = await browser.newPage()
    await page.goto('http://127.0.0.1:5500/index.html')
    await page.screenshot({ path: 'screenshot.png', fullPage: true })
    // await browser.close()
})