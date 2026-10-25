/* Optional: requires Playwright and a Chromium executable. No runtime dependency. */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const {spawn}=require('child_process');
const path=require('path');
const assert=require('assert');
(async()=>{
 const root=path.resolve(__dirname,'..');
 const server=spawn('python3',[path.join(root,'scripts/demo.py')],{env:{...process.env,EDGE_DEMO_PASSWORD:'browser-test-password-2026'},stdio:['ignore','pipe','pipe']});
 let browser;
 try{
  await new Promise((resolve,reject)=>{let out='';const timeout=setTimeout(()=>reject(Error('Demo startup timeout')),15000);server.stdout.on('data',d=>{out+=d;if(out.includes('Edge Panel on')){clearTimeout(timeout);resolve();}});server.on('exit',code=>reject(Error('Demo exited '+code)));});
  browser=await chromium.launch({executablePath:process.env.CHROME_PATH||undefined,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:9090/');await page.locator('#password').fill('browser-test-password-2026');await page.locator('#login-form button').click();await page.locator('#app').waitFor({state:'visible'});
  assert.strictEqual(await page.locator('.field').count(),18);
  if(process.env.SCREENSHOT_DIR)await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'desktop.png'),fullPage:true});
  await page.locator('[data-tab="network"]').click();await page.locator('#EDGE_ADDR').fill(':9443');await page.locator('#validate').click();await page.locator('#toast').filter({hasText:'معتبرند'}).waitFor();
  await page.locator('#apply').click();await page.locator('#confirm-ok').click();await page.locator('#toast').filter({hasText:'سرویس آماده است'}).waitFor();
  await page.locator('[data-tab="overview"]').click();await page.locator('#metric-status').filter({hasText:'در حال اجرا'}).waitFor();
  await page.locator('[data-tab="history"]').click();assert.strictEqual(await page.locator('.history-row').count(),1);
  await page.locator('.history-row button').click();await page.locator('#confirm-ok').click();await page.locator('#toast').filter({hasText:'بازیابی شد'}).waitFor();
  await page.locator('[data-tab="logs"]').click();await page.locator('#audit-logs').filter({hasText:'apply'}).waitFor();
  await page.locator('[data-tab="source"]').click();await page.locator('#source-code').filter({hasText:'package main'}).waitFor();
  await page.setViewportSize({width:390,height:844});await page.locator('[data-tab="network"]').click();assert.strictEqual(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile horizontal overflow');
  if(process.env.SCREENSHOT_DIR)await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'mobile.png'),fullPage:true});
  await page.locator('[data-tab="security"]').click();await page.locator('#EDGE_HMAC_SECRET').fill('short');await page.locator('#validate').click();await page.locator('#toast').filter({hasText:'حداقل'}).waitFor();
  await page.locator('#refresh').click();await page.locator('#confirm-ok').click();await page.locator('#dirty-text').filter({hasText:'همگام'}).waitFor();
  await page.locator('#logout').click();await page.locator('#login').waitFor({state:'visible'});assert.deepStrictEqual(errors,[]);
  console.log('PASS: browser login, all 18 controls, validation, apply, rollback, logs, source, mobile overflow, invalid secret, reload and logout; no page errors.');
 }finally{if(browser)await browser.close();server.kill('SIGTERM');}
})().catch(e=>{console.error(e);process.exitCode=1;});
