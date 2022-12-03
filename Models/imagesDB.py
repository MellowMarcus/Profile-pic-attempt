from App.database import db

#Images uploaded by users
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId =  db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rankings = db.relationship('Ranking', backref='ranking', lazy=True, cascade="all, delete-orphan")
    source = db.Column(db.String, nullable=False, unique=True)

    def __init__(self, userId):
        self.userId = userId

    def toJSON(self):
        return{
            'id': self.id,
            'userId': self.userId,
            'rankings': [ranking.toJSON() for ranking in self.rankings],
            'source' : self.source 
        }
