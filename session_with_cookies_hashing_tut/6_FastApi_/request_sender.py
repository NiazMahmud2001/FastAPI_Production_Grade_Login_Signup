# 1 -> in browser type: http://127.0.0.1:port/docs    -> this gives fast api UI for testing
# 2 -> user httpx -> this can store cookies (used in session)


import httpx, asyncio

async def main():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8786") as client:
        # signup
        r1 = await client.post("/signup", json={
            "userName": "Niaz Mahmud",
            "password": "@Niaz01010101",
            "userDescription": "hellow tummy",
            "userEmail": "niaz@gmail.com",
            "age": 19,
        })
        print("signup:", r1.status_code, r1.text)
        print("="*100)
        print()
        print()


        # first login -> set up cookies 
        r2 = await client.post("/login", json={
            "userName": "Niaz Mahmud",
            "password": "@Niaz01010101",
        })
        print("first lofin with credentials:", r2.status_code, r2.text)
        print("cookies:", dict(client.cookies))
        print("="*100)
        print()
        print()


        # Now -> direct login with cookies
        r3 = await client.post("/login")
        print("login with Cookies info:", r3.status_code, r3.text)

asyncio.run(main())







