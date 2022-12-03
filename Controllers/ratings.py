from App.models import Rating, User
from App.database import db

def create_rating(creatorId, targetId, score):
    newRating = Rating(creatorId=creatorId, targetId=targetId, score=score)
    db.session.add(newRating)
    db.session.commit()
    return newRating

def get_ratings_by_target(targetId):
    ratings = Rating.query.filter_by(targetId=targetId)
    if not ratings:
        return []
    ratings = [rating.toJSON() for rating in ratings]
    return ratings

def get_ratings_by_creator(creatorId):
    ratings = Rating.query.filter_by(creatorId=creatorId)
    if not ratings:
        return []
    ratings = [rating.toJSON() for rating in ratings]
    return ratings

def get_rating_by_actors(creatorId, targetId):
    if User.query.get(creatorId) and User.query.get(targetId):
        rating = Rating.query.filter_by(creatorId=creatorId, targetId=targetId).first()
        return rating
    return None

def get_rating(id):
    rating = Rating.query.get(id)
    return rating

def get_all_ratings():
    return Rating.query.all()

def get_all_ratings_json():
    ratings = Rating.query.all()
    if not ratings:
        return []
    ratings = [rating.toJSON() for rating in ratings]
    return ratings

def update_rating(id, score):
    rating = get_rating(id)
    if rating:
        rating.score = score
        db.session.add(rating)
        db.session.commit()
        return rating
    return None

# def delete_rating(id):
#     rating = get_rating(id)
#     if rating:
#         db.session.delete(rating)
#         return db.session.commit()
#     return None

def get_calculated_rating(targetId):
    ratings = Rating.query.filter_by(targetId=targetId)
    total = 0
    if ratings:
        for rating in ratings:
            total = total + rating.score
        if ratings.count() != 0:
            total = total / ratings.count()
        return total
    return None

def get_level(id):
    ratings = get_ratings_by_creator(id)
    if ratings:
        level = 0;
        for rating in ratings:
            level = level + 1
        return level
    return None
