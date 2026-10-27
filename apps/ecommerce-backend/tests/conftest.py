import app.models
import pytest
from app.core.config import get_settings
from app.core.database import Base, close_db, get_engine, get_session_maker
from app.core.redis import close_redis
from app.main import app
from app.seed import seed_database
from httpx import ASGITransport, AsyncClient


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment(tmp_path_factory):
    """Ensure an isolated temporary SQLite database and fake Redis are used for test runs."""
    settings = get_settings()
    settings.ENVIRONMENT = "test"
    test_db_path = tmp_path_factory.mktemp("test_db") / "test_cybershield.db"
    settings.SQLITE_FALLBACK_URL = f"sqlite+aiosqlite:///{test_db_path.as_posix()}"
    settings.USE_SQLITE_FALLBACK = True
    settings.REDIS_USE_FAKEREDIS_FALLBACK = True
    return settings


@pytest.fixture(scope="session", autouse=True)
async def initialize_test_database(setup_test_environment):
    """Ensure tables are created and seed data is present once for the test session."""
    engine = await get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = await get_session_maker()
    async with session_maker() as session:
        await seed_database(session)

    yield


@pytest.fixture
async def async_client():
    """Async HTTP client for testing API endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def db_session():
    """Isolated database session fixture for testing ORM entities directly."""
    session_maker = await get_session_maker()
    async with session_maker() as session:
        yield session


@pytest.fixture(scope="session", autouse=True)
async def cleanup_connections():
    """Ensure connections are closed cleanly after all tests in the session complete."""
    yield
    await close_db()
    await close_redis()
