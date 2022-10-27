from webportal import db


def update_db() -> None:
    try:
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def add_db(new_obj) -> None:
    try:
        db.session.add(new_obj)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def del_db(target_obj) -> None:
    try:
        db.session.delete(target_obj)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def update_db_no_close() -> None:
    try:
        db.session.commit()
    except:
        db.session.rollback()


def add_db_no_close(new_obj) -> None:
    try:
        db.session.add(new_obj)
        db.session.commit()
    except:
        db.session.rollback()


def del_db_no_close(target_obj) -> None:
    try:
        db.session.delete(target_obj)
        db.session.commit()
    except:
        db.session.rollback()

