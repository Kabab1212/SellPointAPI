from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, constr
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import List, Optional
import databases
import sqlalchemy
from datetime import datetime, timedelta

# CONFIGURATION
DATABASE_URL = "sqlite:///./ecommerce.db"
SECRET_KEY = "verysecretkey12345"  # Change in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# DATABASE SETUP
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email", sqlalchemy.String, unique=True, index=True),
    sqlalchemy.Column("hashed_password", sqlalchemy.String),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, default=True),
    sqlalchemy.Column("role", sqlalchemy.String, default="customer"),  # admin/staff/customer
)

products = sqlalchemy.Table(
    "products",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, index=True),
    sqlalchemy.Column("description", sqlalchemy.String),
    sqlalchemy.Column("price", sqlalchemy.Float),
    sqlalchemy.Column("stock", sqlalchemy.Integer),
    sqlalchemy.Column("variant", sqlalchemy.String, nullable=True),  # e.g., "size: M, color: red"
)

orders = sqlalchemy.Table(
    "orders",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.Column("status", sqlalchemy.String, default="pending"),  # pending, shipped, cancelled
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

order_items = sqlalchemy.Table(
    "order_items",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("order_id", sqlalchemy.Integer),
    sqlalchemy.Column("product_id", sqlalchemy.Integer),
    sqlalchemy.Column("quantity", sqlalchemy.Integer),
)

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

# SECURITY & AUTH
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="E-commerce Inventory & Order Management API")

# UTILS

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str):
    query = users.select().where(users.c.email == email)
    user = await database.fetch_one(query)
    return user

async def authenticate_user(email: str, password: str):
    user = await get_user(email)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(email=email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if not current_user["is_active"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def admin_required(user: dict = Depends(get_current_active_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

# SCHEMAS
class UserCreate(BaseModel):
    email: EmailStr
    password: constr(min_length=6)
    role: Optional[str] = "customer"

class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str

class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    price: float
    stock: int
    variant: Optional[str] = None

class ProductOut(ProductCreate):
    id: int

class OrderItemCreate(BaseModel):
    product_id: int
    quantity: int

class OrderCreate(BaseModel):
    items: List[OrderItemCreate]

class OrderOut(BaseModel):
    id: int
    user_id: int
    status: str
    created_at: datetime
    items: List[OrderItemCreate]

# ROUTES

@app.get("/")
async def root():
    return {"message": "E-commerce Inventory API is running"}

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/users/", response_model=UserOut)
async def create_user(user: UserCreate):
    user_in_db = await get_user(user.email)
    if user_in_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    query = users.insert().values(email=user.email, hashed_password=hashed_password, role=user.role)
    user_id = await database.execute(query)
    return {**user.dict(), "id": user_id}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["email"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/products/", response_model=ProductOut, dependencies=[Depends(admin_required)])
async def create_product(product: ProductCreate):
    query = products.insert().values(**product.dict())
    product_id = await database.execute(query)
    return {**product.dict(), "id": product_id}

@app.get("/products/", response_model=List[ProductOut])
async def list_products():
    query = products.select()
    return await database.fetch_all(query)

@app.put("/products/{product_id}", response_model=ProductOut, dependencies=[Depends(admin_required)])
async def update_product(product_id: int, product: ProductCreate):
    query = products.update().where(products.c.id == product_id).values(**product.dict())
    await database.execute(query)
    query = products.select().where(products.c.id == product_id)
    updated_product = await database.fetch_one(query)
    return updated_product

@app.delete("/products/{product_id}", status_code=204, dependencies=[Depends(admin_required)])
async def delete_product(product_id: int):
    query = products.delete().where(products.c.id == product_id)
    await database.execute(query)
    return

@app.post("/orders/", response_model=OrderOut)
async def create_order(order: OrderCreate, current_user: dict = Depends(get_current_active_user)):
    # Check stock availability and reserve items
    for item in order.items:
        product_query = products.select().where(products.c.id == item.product_id)
        product = await database.fetch_one(product_query)
        if not product:
            raise HTTPException(status_code=404, detail=f"Product {item.product_id} not found")
        if product["stock"] < item.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for product {product['name']}")

    # Deduct stock
    for item in order.items:
        current_stock = (await database.fetch_one(products.select().where(products.c.id == item.product_id)))["stock"]
        new_stock = current_stock - item.quantity
        await database.execute(
            products.update().where(products.c.id == item.product_id).values(stock=new_stock)
        )

    # Create order
    order_query = orders.insert().values(user_id=current_user["id"], status="pending", created_at=datetime.utcnow())
    order_id = await database.execute(order_query)

    # Create order items
    for item in order.items:
        await database.execute(order_items.insert().values(order_id=order_id, product_id=item.product_id, quantity=item.quantity))

    return {
        "id": order_id,
        "user_id": current_user["id"],
        "status": "pending",
        "created_at": datetime.utcnow(),
        "items": order.items
    }

@app.get("/orders/", response_model=List[OrderOut], dependencies=[Depends(admin_required)])
async def list_orders():
    query = orders.select()
    orders_list = await database.fetch_all(query)
    result = []
    for order in orders_list:
        items_query = order_items.select().where(order_items.c.order_id == order["id"])
        items = await database.fetch_all(items_query)
        result.append({
            "id": order["id"],
            "user_id": order["user_id"],
            "status": order["status"],
            "created_at": order["created_at"],
            "items": [{"product_id": i["product_id"], "quantity": i["quantity"]} for i in items]
        })
    return result

@app.put("/orders/{order_id}/status", dependencies=[Depends(admin_required)])
async def update_order_status(order_id: int, status: str):
    if status not in ("pending", "shipped", "cancelled"):
        raise HTTPException(status_code=400, detail="Invalid status")
    query = orders.update().where(orders.c.id == order_id).values(status=status)
    await database.execute(query)
    return {"order_id": order_id, "new_status": status}

@app.get("/analytics/sales", dependencies=[Depends(admin_required)])
async def sales_report():
    query = """
    SELECT products.name, SUM(order_items.quantity) as total_sold
    FROM order_items
    JOIN products ON order_items.product_id = products.id
    GROUP BY products.name
    ORDER BY total_sold DESC
    """
    results = await database.fetch_all(query)
    return results
