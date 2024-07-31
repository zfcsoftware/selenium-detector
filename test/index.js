const puppeteer = require('puppeteer-extra')

const StealthPlugin = require('puppeteer-extra-plugin-stealth')
puppeteer.use(StealthPlugin())


puppeteer.launch({
    headless: "new",
    args: ['--no-sandbox', '--disable-setuid-sandbox', "--disable-blink-features=AutomationControlled", '--disable-infobars']
}).then(async browser => {
    const page = await browser.newPage()
    await page.goto('https://zfcsoftware.github.io/selenium-detector/')
    await page.screenshot({ path: 'screenshot.png', fullPage: true })
    await browser.close()
})