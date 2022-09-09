from webportal import db

def update_db():
    try:
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()    

def add_db(new_obj):
    try:
        db.session.add(new_obj)
        db.session.commit()
    except:
        db.session.rollback()
    finally:
        db.session.close()