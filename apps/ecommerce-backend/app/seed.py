from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.core.security import get_password_hash
from app.models.order import Order, OrderItem, Payment
from app.models.product import Product
from app.models.user import User

SEED_USERS = [
    {
        "email": "admin@cybershield.io",
        "full_name": "Security Administrator",
        "password": "AdminPass123!",
        "role": "admin",
    },
    {
        "email": "alice@cybershield.io",
        "full_name": "Alice Shopper",
        "password": "AlicePass123!",
        "role": "customer",
    },
    {
        "email": "bob@cybershield.io",
        "full_name": "Bob Regular",
        "password": "BobPass123!",
        "role": "customer",
    },
    {
        "email": "attacker@cybershield.io",
        "full_name": "Mallory Attacker",
        "password": "AttackerPass123!",
        "role": "customer",
    },
]

SEED_PRODUCTS = [
    {
        "name": "YubiKey 5 NFC Hardware Key",
        "slug": "yubikey-5-nfc",
        "description": "Multi-protocol hardware authenticator for FIDO2/WebAuthn, U2F, and Smart Card.",
        "category": "Hardware Security",
        "price": 55.0,
        "stock": 100,
    },
    {
        "name": "Flipper Zero Multi-Tool Device",
        "slug": "flipper-zero",
        "description": "Portable multi-tool device for pen-testers, geeks, and RFID/Sub-1GHz radio research.",
        "category": "Hardware Security",
        "price": 169.0,
        "stock": 40,
    },
    {
        "name": "ThinkPad X1 Carbon Gen 12",
        "slug": "thinkpad-x1-carbon",
        "description": "Ultra-lightweight security hardened laptop with TPM 2.0 and biometric authentication.",
        "category": "Laptops",
        "price": 1899.0,
        "stock": 15,
    },
    {
        "name": "MacBook Pro 14 M3",
        "slug": "macbook-pro-14",
        "description": "Apple Silicon development laptop with Secure Enclave and Hardware Biometrics.",
        "category": "Laptops",
        "price": 1999.0,
        "stock": 10,
    },
    {
        "name": "WiFi Pineapple Enterprise",
        "slug": "wifi-pineapple",
        "description": "Enterprise wireless network auditing device for rogue AP detection.",
        "category": "Network Security",
        "price": 249.99,
        "stock": 30,
    },
    {
        "name": "USB Rubber Ducky Keystroke Injector",
        "slug": "usb-rubber-ducky",
        "description": "Automated keystroke injection attack tool disguised as a generic flash drive.",
        "category": "Hardware Security",
        "price": 79.99,
        "stock": 50,
    },
    {
        "name": "UniFi Dream Machine Pro",
        "slug": "unifi-dream-machine",
        "description": "10G enterprise gateway and network security router with built-in IDS/IPS.",
        "category": "Network Security",
        "price": 379.0,
        "stock": 20,
    },
    {
        "name": "Nitrokey 3A NFC FIDO2 Key",
        "slug": "nitrokey-3a-nfc",
        "description": "Open source security key with NFC, firmware verification, and Rust crypto core.",
        "category": "Hardware Security",
        "price": 49.0,
        "stock": 80,
    },
    {
        "name": "Proxmark3 RDV4 RFID Kit",
        "slug": "proxmark3-rdv4",
        "description": "High-performance RFID research and emulation tool supporting LF and HF bands.",
        "category": "Hardware Security",
        "price": 299.0,
        "stock": 25,
    },
    {
        "name": "IronKey Vault Privacy 2TB SSD",
        "slug": "ironkey-vault-2tb",
        "description": "FIPS 197 certified hardware-encrypted external SSD with XTS-AES 256-bit encryption.",
        "category": "Accessories",
        "price": 289.0,
        "stock": 35,
    },
]


async def seed_database(db: AsyncSession):
    """Seed initial products, test accounts, and baseline sample orders if database is empty."""
    # Check if users already exist
    user_check = await db.execute(select(User).limit(1))
    if user_check.scalar_one_or_none():
        return

    logger.info("Database is unpopulated. Seeding initial testbed data...")

    created_users = {}
    for u_data in SEED_USERS:
        user = User(
            email=u_data["email"],
            full_name=u_data["full_name"],
            hashed_password=get_password_hash(u_data["password"]),
            role=u_data["role"],
        )
        db.add(user)
        created_users[u_data["email"]] = user

    created_products = {}
    for p_data in SEED_PRODUCTS:
        product = Product(
            name=p_data["name"],
            slug=p_data["slug"],
            description=p_data["description"],
            category=p_data["category"],
            price=p_data["price"],
            stock=p_data["stock"],
            is_active=True,
        )
        db.add(product)
        created_products[p_data["slug"]] = product

    await db.flush()

    # Seed Baseline Order 1001 for Alice (Target for BOLA)
    alice = created_users["alice@cybershield.io"]
    yubikey = created_products["yubikey-5-nfc"]
    flipper = created_products["flipper-zero"]

    order_1001 = Order(
        order_number=1001,
        user_id=alice.id,
        total_amount=224.0,
        status="paid",
        shipping_address="42 Security Boulevard, Tech Valley, CA 94016",
        items=[
            OrderItem(
                product_id=yubikey.id,
                quantity=1,
                unit_price=yubikey.price,
                total_price=yubikey.price,
            ),
            OrderItem(
                product_id=flipper.id,
                quantity=1,
                unit_price=flipper.price,
                total_price=flipper.price,
            ),
        ],
        payment=Payment(
            payment_method="credit_card",
            amount=224.0,
            status="success",
            transaction_reference="TX-ALICE-1001",
        ),
    )
    db.add(order_1001)

    # Seed Baseline Order 1002 for Bob
    bob = created_users["bob@cybershield.io"]
    thinkpad = created_products["thinkpad-x1-carbon"]

    order_1002 = Order(
        order_number=1002,
        user_id=bob.id,
        total_amount=1899.0,
        status="paid",
        shipping_address="100 Enterprise Way, Suite 400, Austin, TX 78701",
        items=[
            OrderItem(
                product_id=thinkpad.id,
                quantity=1,
                unit_price=thinkpad.price,
                total_price=thinkpad.price,
            ),
        ],
        payment=Payment(
            payment_method="credit_card",
            amount=1899.0,
            status="success",
            transaction_reference="TX-BOB-1002",
        ),
    )
    db.add(order_1002)

    await db.commit()
    logger.info("Successfully seeded users, products, and baseline orders.")
