from App.models import Image
from App.database import db

def create_image(userId):
    newImage = Image(userId=userId)
    db.session.add(newImage)
    db.session.commit()
    return newImage

def get_image(id):
    return Image.query.get(id)

def get_image_json(id):
    image = Image.query.get(id)
    if not image:
        return []
    image = image.toJSON()
    return image

def get_images_by_userid(userId):
    return Image.query.filter_by(userId=userId)

def get_images_by_userid_json(userId):
    images = Image.query.filter_by(userId=userId)
    if not images:
        return []
    images = [image.toJSON() for image in images]
    return images

def get_all_images():
    return Image.query.all()

def get_all_images_json():
    images = Image.query.all()
    if images:
        images = [image.toJSON() for image in images]
        return images
    return []

def delete_image(id):
    image = get_image(id)
    if image:
        db.session.delete(image)
        return db.session.commit()
    return None
