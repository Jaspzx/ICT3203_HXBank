from webportal import db


def update_db() -> None:
    """
    Update database
    :return None:
    """
    try:
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def add_db(new_obj) -> None:
    """
    Add database entry
    :return None:
    """
    try:
        db.session.add(new_obj)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def del_db(target_obj) -> None:
    """
    Delete database entry
    :return None:
    """
    try:
        db.session.delete(target_obj)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()


def update_db_no_close() -> None:
    """
    Update database but session is not closed
    :return None:
    """
    try:
        db.session.commit()
    except:
        db.session.rollback()


def add_db_no_close(new_obj) -> None:
    """
    Add database entry but session is not closed
    :return None:
    """
    try:
        db.session.add(new_obj)
        db.session.commit()
    except:
        db.session.rollback()


def del_db_no_close(target_obj) -> None:
    """
    Delete database entry but session is not closed
    :return None:
    """
    try:
        db.session.delete(target_obj)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()

