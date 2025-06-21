"""
recipe_backend FastAPI app.

This backend manages recipes, user authentication, and provides RESTful APIs for the RecipeHub app.

Features:
- View all recipes
- Search recipes
- Add/Edit/Delete recipes
- User authentication (JWT)
- Swagger/OpenAPI documentation
"""

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(
    title="RecipeHub Backend API",
    version="1.0.0",
    description=(
        "Handles recipe data management, user profiles, and all backend operations "
        "for RecipeHub."
    ),
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "recipes", "description": "Recipe management"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Simple in-memory stores for demo purposes
users_db = {}
recipes_db = {}
recipe_id_counter = 1

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


class Token(BaseModel):
    access_token: str = Field(..., description="Access token")
    token_type: str = Field(
        ..., description="Type of the token (bearer)"
    )


class User(BaseModel):
    id: int = Field(..., description="User ID")
    username: str = Field(..., description="Unique username")
    full_name: Optional[str] = Field(
        None, description="Full name of the user"
    )


class UserCreate(BaseModel):
    username: str = Field(..., description="Unique username")
    password: str = Field(..., description="Password")
    full_name: Optional[str] = Field(
        None, description="Full name of the user"
    )


class Recipe(BaseModel):
    id: int = Field(..., description="Recipe ID")
    title: str = Field(..., description="Recipe title")
    description: str = Field(..., description="Short recipe description")
    ingredients: List[str] = Field(..., description="Ingredients list")
    steps: List[str] = Field(..., description="Preparation steps")
    author_id: int = Field(..., description="User ID of recipe author")
    created_at: datetime = Field(..., description="Timestamp of creation")
    updated_at: Optional[datetime] = Field(
        None, description="Timestamp of last update"
    )


class RecipeCreate(BaseModel):
    title: str = Field(..., description="Recipe title")
    description: str = Field(..., description="Short recipe description")
    ingredients: List[str] = Field(..., description="Ingredients list")
    steps: List[str] = Field(..., description="Preparation steps")


# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Verify password using passlib context."""
    return pwd_context.verify(plain_password, hashed_password)


# PUBLIC_INTERFACE
def get_password_hash(password):
    """Return hashed password."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def authenticate_user(username: str, password: str):
    """Authenticate user by username and password."""
    user = users_db.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


# PUBLIC_INTERFACE
def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
):
    """Create JWT access token for the given data."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get the currently authenticated user from the JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if (
            username is None
            or username not in users_db
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        user_data = users_db[username]
        return User(
            id=user_data["id"],
            username=username,
            full_name=user_data["full_name"]
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )


# --- AUTH ROUTES ---


@app.post(
    "/auth/register",
    summary="Register a new user",
    description="Create a new user account.",
    tags=["auth"],
    response_model=User
)
def register(user: UserCreate = Body(...)):
    if user.username in users_db:
        raise HTTPException(
            status_code=400, detail="Username already registered"
        )
    user_id = len(users_db) + 1
    users_db[user.username] = {
        "id": user_id,
        "username": user.username,
        "hashed_password": get_password_hash(user.password),
        "full_name": user.full_name
    }
    return User(
        id=user_id,
        username=user.username,
        full_name=user.full_name
    )


@app.post(
    "/auth/token",
    summary="Get access token",
    description="Authenticate and receive a JWT token.",
    tags=["auth"],
    response_model=Token
)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get(
    "/auth/profile",
    summary="Get current user profile",
    description="Retrieve details of the currently authenticated user.",
    tags=["auth"],
    response_model=User
)
def profile(current_user: User = Depends(get_current_user)):
    return current_user


# --- RECIPE ROUTES ---


@app.post(
    "/recipes/",
    summary="Add a new recipe",
    description="Add a new recipe (requires authentication).",
    tags=["recipes"],
    response_model=Recipe
)
def add_recipe(recipe: RecipeCreate, current_user: User = Depends(get_current_user)):
    global recipe_id_counter
    rid = recipe_id_counter
    recipe_id_counter += 1
    now = datetime.utcnow()
    recipes_db[rid] = {
        "id": rid,
        "title": recipe.title,
        "description": recipe.description,
        "ingredients": recipe.ingredients,
        "steps": recipe.steps,
        "author_id": current_user.id,
        "created_at": now,
        "updated_at": now
    }
    return Recipe(**recipes_db[rid])


@app.get(
    "/recipes/",
    summary="List recipes",
    description="Get a list of all recipes. Optionally filter by search query.",
    tags=["recipes"],
    response_model=List[Recipe]
)
def list_recipes(q: Optional[str] = None):
    def matches(recipe, search):
        return (
            search.lower() in recipe["title"].lower()
            or search.lower() in recipe["description"].lower()
            or any(
                search.lower() in ing.lower()
                for ing in recipe["ingredients"]
            )
        )
    if q:
        results = [
            Recipe(**r) for r in recipes_db.values()
            if matches(r, q)
        ]
    else:
        results = [Recipe(**r) for r in recipes_db.values()]
    return results


@app.get(
    "/recipes/{recipe_id}",
    summary="Get recipe",
    description="Retrieve recipe by ID.",
    tags=["recipes"],
    response_model=Recipe
)
def get_recipe(recipe_id: int):
    r = recipes_db.get(recipe_id)
    if not r:
        raise HTTPException(
            status_code=404, detail="Recipe not found"
        )
    return Recipe(**r)


@app.put(
    "/recipes/{recipe_id}",
    summary="Edit recipe",
    description="Edit an existing recipe (only allowed for author).",
    tags=["recipes"],
    response_model=Recipe
)
def edit_recipe(
    recipe_id: int,
    recipe: RecipeCreate,
    current_user: User = Depends(get_current_user)
):
    r = recipes_db.get(recipe_id)
    if not r:
        raise HTTPException(
            status_code=404, detail="Recipe not found"
        )
    if r["author_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to edit this recipe"
        )
    now = datetime.utcnow()
    r.update(
        title=recipe.title,
        description=recipe.description,
        ingredients=recipe.ingredients,
        steps=recipe.steps,
        updated_at=now
    )
    return Recipe(**r)


@app.delete(
    "/recipes/{recipe_id}",
    status_code=204,
    summary="Delete recipe",
    description="Delete an existing recipe (only allowed for author).",
    tags=["recipes"]
)
def delete_recipe(recipe_id: int, current_user: User = Depends(get_current_user)):
    r = recipes_db.get(recipe_id)
    if not r:
        raise HTTPException(
            status_code=404, detail="Recipe not found"
        )
    if r["author_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to delete this recipe"
        )
    del recipes_db[recipe_id]
    return


@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}
