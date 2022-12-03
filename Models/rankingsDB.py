from App.database import db

#Rankings are created by users when they rate other users' pictures

class Ranking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creatorId =  db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    imageId =  db.Column(db.Integer, db.ForeignKey('image.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    
    
    def __init__(self, creatorId, imageId, score):
        self.creatorId = creatorId
        self.imageId = imageId
        self.score = score
    
    def toJSON(self):
        return{
            'id': self.id,
            'creatorId': self.creatorId,
            'imageId': self.imageId,
            'score': self.score,
        }
