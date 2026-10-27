from app.main import app

from agents.application_mapper.mapper_agent import ApplicationMapperAgent


def test_application_mapper_scan():
    mapper = ApplicationMapperAgent(app=app)
    app_map = mapper.scan()

    assert app_map.app_name == "CyberShield E-Commerce Defense Platform"
    assert app_map.total_endpoints > 10

    # Verify key endpoints are discovered
    endpoints_by_path = {ep.path: ep for ep in app_map.endpoints}
    assert "/api/v1/auth/login" in endpoints_by_path
    assert "/api/v1/products" in endpoints_by_path
    assert "/api/v1/cart" in endpoints_by_path
    assert "/api/v1/orders" in endpoints_by_path
    assert "/api/v1/admin/orders" in endpoints_by_path

    # Verify authorization detection
    login_ep = endpoints_by_path["/api/v1/auth/login"]
    assert not login_ep.auth_required

    cart_ep = endpoints_by_path["/api/v1/cart"]
    assert cart_ep.auth_required

    admin_orders_ep = endpoints_by_path["/api/v1/admin/orders"]
    assert admin_orders_ep.auth_required
    assert admin_orders_ep.admin_only

    # Verify models discovery
    model_names = [m.model_name for m in app_map.models]
    assert "Users" in model_names
    assert "Products" in model_names
    assert "Orders" in model_names
