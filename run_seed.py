import asyncio
import asyncpg
from pathlib import Path

# Need to run asyncpg code
async def seed():
    print("Connecting to DB...")
    # Use the same credentials as your `db.py` config
    try:
        conn = await asyncpg.connect(
            database="ids_system",
            user="postgres",
            password="123",
            host="localhost",
            port=5432
        )
        print("Connected.")
        
        sql_path = Path("C:/Users/Yusse/Workspace/Graduation Project/Full AI Agent/grad_project/seed_test_data.sql")
        sql_content = sql_path.read_text(encoding="utf-8")
        
        print("Executing seed script...")
        await conn.execute(sql_content)
        
        print("Done. Closing connection...")
        await conn.close()
        print("Success! The data has been seeded.")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(seed())
