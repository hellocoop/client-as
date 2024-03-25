

const MOCKIN = 'http://localhost:3333/'
const CLIENT_HOME = 'http://localhost:8000'
const CLIENT_API = CLIENT_HOME+'/api/auth'

const AS_HOME = 'http://localhost:3000/api/auth'

import { test, expect } from '@playwright/test';

const loggedOut = {isLoggedIn:false}
const loggedIn = {
    isLoggedIn:true,
    sub:"00000000-0000-0000-0000-00000000",
    name:"John Smith",
    email:"john.smith@example.com",
    picture:"https://pictures.hello.coop/mock/portrait-of-john-smith.jpeg",
    email_verified:true
}



/* 
* used for debugging
*
const trace = (page) => {
    page.on('request', async request => {
        console.log('Request:', request.method(), request.url());
        console.log('\theaders:', request.headers());
      });
      
    page.on('response', async response => {
        console.log('Response:', response.status(), response.url());
        console.log('\tresponse headers:', response.headers());
    });
    
    page.on('requestfailed', request => {
        console.log('Request failed:', request.method(), request.url(), request?.failure()?.errorText);
        console.log('\theaders:', request.headers());
    });
}
*/

// test.describe(`Testing ${CLIENT_HOME}`, () => {

//     test.beforeEach(async ({ page }) => {        
//         await page.goto(CLIENT_API+'?op=logout')
//         const response = await page.request.get(CLIENT_API+'?op=auth')
//         const json = await response.json()
//         expect(json).toEqual(loggedOut)
//     })

//     test('Logged Out', async ({ page, context }) => {
//         const response = await page.request.get(CLIENT_API+'?op=logout');
//         const json = await response.json()
//         expect(json).toEqual(loggedOut)
//     })
//     test('login', async ({ page, context }) => {
//         // this request fails in webkit -- and cookies are not set
//         // TBD - figure out why so we can test webkit
//         await page.goto(CLIENT_API+'?op=login')
//         const body = await page.textContent('body');

//         try {
//             const json = JSON.parse(body as string);
//             delete json.iat
//             expect(json).toEqual(loggedIn)
//         }
//         catch (e) {
//             expect(e).toBeNull()
//         }
//     })
//     test('Logged In', async ({ page }) => {
//         await page.goto(CLIENT_API+'?op=login')
//         const response = await page.request.get(CLIENT_API+'?op=auth');
//         const json = await response.json()
//         delete json.iat
//         expect(json).toEqual(loggedIn)
//     })
//     test('auth', async ({ page }) => {
//         await page.goto(CLIENT_API+'?op=login')
//         const response = await page.request.get(CLIENT_API+'?op=auth');
//         const json = await response.json()
//         delete json.iat
//         expect(json).toEqual(loggedIn)
//     })

// });

test.describe(`Testing ${AS_HOME}`, () => {

    test.beforeEach(async ({ page }) => {        
        await page.goto(CLIENT_API+'?op=logout')
        const response = await page.request.get(CLIENT_API+'?op=auth')
        const json = await response.json()
        expect(json).toEqual(loggedOut)
    })

    test('AS login', async ({ page, request, context }) => {
        const response = await request.post(AS_HOME+'/token', {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: 'grant_type=cookie_token&client_id=docker-test'
        })
        const jsonAS = await response.json()

console.log('jsonAS', jsonAS)

        const cookies = await context.cookies()
        console.log('cookies', cookies)

        expect(jsonAS).toBeDefined()
        expect(jsonAS.loggedIn).toBe(false)
        const nonce = jsonAS.nonce
        expect(nonce).toBeDefined()
        // this request fails in webkit -- and cookies are not set
        // TBD - figure out why so we can test webkit
        await page.goto(CLIENT_API+`?op=login&nonce=${nonce}`)
        const body = await page.textContent('body');

        try {
            const json = JSON.parse(body as string);
            delete json.iat
            expect(json).toEqual(loggedIn)
        }
        catch (e) {
            expect(e).toBeNull()
        }

console.log('cookies-', await context.cookies())


        const response2 = await request.post(AS_HOME+'/token', {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: 'grant_type=cookie_token&client_id=docker-test'
        })
        const jsonAS2 = await response2.json()

        console.log('jsonAS2', jsonAS2)

        const cookies2 = await context.cookies()
        console.log('cookies2', cookies2)

        expect(jsonAS2).toBeDefined()
        expect(jsonAS2.loggedIn).toBe(true)

        const response3 = await request.get(AS_HOME+'/introspect')
        const jsonAS3 = await response3.json()

console.log('jsonAS3', jsonAS3)

        expect(jsonAS3).toBeDefined()
        const { sub, iss } = jsonAS3
        expect(sub).toEqual(loggedIn.sub)
        expect(iss).toEqual(AS_HOME)
    })

});
