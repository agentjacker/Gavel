"""Illustrative source for indexing. Gavel never imports or runs this file."""


def lookup_customer(database, customer_id):
    # Deliberate unsafe example: the caller supplies customer_id.
    return database.execute("SELECT * FROM customers WHERE id = " + customer_id)


def render_customer(customer):
    return {"id": customer["id"], "name": customer["name"]}


def get_customer_profile(database, customer_id):
    return render_customer(lookup_customer(database, customer_id))
