import bcrypt
import uuid
from database import connection
from pydantic import BaseModel


class UserIn(BaseModel):
    username: str
    password: str


class User(BaseModel):
    user_id: str
    username: str
    password_hash: str

    def __init__(self, user_id, username, password_hash):
        super().__init__(
            user_id=user_id, username=username, password_hash=password_hash
        )

    def verify_password(self, password):
        # doesn't need the salt value as it automatically generates it from the hash, check below
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )


# bcrypt.checkpw() checks if a password matches a hash that was previously
# generated using bcrypt's bcrypt.hashpw() function. when you use bcrypt.hashpw()
# to hash a password, the library automatically generates a random salt value and
# includes it in the hash output. this salt is used to increase the security of the
# hash and prevent attacks like rainbow table attacks and precomputed hash attacks.

# when you call bcrypt.checkpw() to verify a password, the function extracts the
# salt value from the hash output and uses it to re-calculate the hash of the password
# being verified. it then compares the new hash with the hash that was previously
# generated and stored. if the two hashes match, it means that the password being
# verified is the same as the original password that was hashed and the function
# returns true. otherwise, it returns false.

# so even though bcrypt.checkpw() doesn't require you to pass in a salt value directly,
# it's still able to extract the salt value from the hash output and use it to verify the password.


# helper functions
def insert_user(username: str, password: str) -> None:
    conn = connection()
    cursor = conn.cursor()

    salt = connection().execute("SELECT * FROM salt").fetchone()[0]
    password_hash = bcrypt.hashpw(password.encode("utf-8"), salt=salt)

    cursor.execute(
        "INSERT INTO users (user_id, username, password_hash) VALUES (?, ?, ?)",
        (str(uuid.uuid4()), username, password_hash),
    )

    conn.commit()
    cursor.close()
    conn.close()


def get_user_by_username(username: str) -> User:
    conn = connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user is None:
        return None

    return User(*user)


def get_user_by_id(id: str) -> User:
    conn = connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE user_id = ?", (id,))
    user = cursor.fetchone()

    if user is None:
        return None
    return User(*user)
