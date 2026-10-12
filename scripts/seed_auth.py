"""Create or refresh the local relying-party API credential."""
import hashlib
import os

from sqlalchemy import select

from auth_service.config import RP_CLIENT_SECRET
from auth_service.db import SessionLocal, init_db, utcnow
from auth_service.models.relying_party import RelyingParty


def main() -> None:
    init_db()
    name = os.getenv("RP_NAME", "Gallifrey demo RP")
    secret_hash = hashlib.sha256(RP_CLIENT_SECRET.encode()).hexdigest()
    with SessionLocal() as db:
        relying_party = db.scalar(
            select(RelyingParty).where(RelyingParty.name == name)
        )
        if relying_party is None:
            relying_party = RelyingParty(
                name=name,
                client_secret_hash=secret_hash,
                status="ACTIVE",
                created_at=utcnow(),
            )
            db.add(relying_party)
        else:
            relying_party.client_secret_hash = secret_hash
            relying_party.status = "ACTIVE"
        db.commit()
        print(f"Ready: {name} (rp_id={relying_party.id})")


if __name__ == "__main__":
    main()
