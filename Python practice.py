from pydantic import BaseModel

class Item(BaseModel):
    name: str
    price: float
    in_stock: bool = True
from fastapi import FastAPI

app = FastAPI()

@app.post("/items/")
async def create_item(item: Item):
    return {"message": f"{item.name} added at ${item.price}", "stock": item.in_stock}
