from flask import Flask
from app import app
from models import *
from flask_restful import Resource, Api
api = Api(app)

class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}

api.add_resource(HelloWorld, '/')

class CategoryResource(Resource):
    def get(self):
        categories = Category.query.all()
        return {'categories' :[{
            'id': category.id,
            'name': category.name
        }for category in categories]
        }

api.add_resource(CategoryResource,'/api/category')