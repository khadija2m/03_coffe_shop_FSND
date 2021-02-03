import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth, get_token_auth_header

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()

# -----------------------------------------------------------
# ROUTES
# ------------------------------------------------------------


#  GET /drinks
# ---------------------------------------------
@app.route('/drinks')
def get_drinks():

    drink_list = Drink.query.all()
    drinks = [drink.short() for drink in drink_list]

    return jsonify({
        'success': True,
        'drinks': drinks
    })


# GET /drinks-detail
# --------------------------------------
@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def get_drink_detail(payload):
    drink_list = Drink.query.all()

    return jsonify({
        'success': True,
        'drinks': [drink.long() for drink in drink_list]
    })


#  POST /drinks : create a new row in the drinks
# -----------------------------------------
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drink(payload):
    if not request.data:
        abort(403)
    info = request.get_json()

    new_title = info.get('title', None)
    new_recipe = info.get('recipe', None)

    drink = Drink(title=new_title, recipe=json.dumps(new_recipe))
    drink.insert()

    drinks = Drink.query.filter(Drink.id == drink.id)

    return jsonify({
        'success': True,
        'drinks': drink.long()
    })


# PATCH /drinks/<id>
# --------------------------------------------------------
@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, drink_id):
    info = request.get_json()

    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

    if not drink:
        abort(404)
    try:
        dr_title = info.get('title', None)
        dr_recipe = info.get('recipe', None)
        if dr_title:
            drink.title = dr_title

        if dr_recipe:
            drink.recipe = json.dumps(dr_recipe)

        drink.update()

    except:
        abort(400)

    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    })


#    DELETE /drinks/<id> : where <id> is the existing model id
# ----------------------------------------------------------
@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, drink_id):

    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
    try:
        if not drink:
            abort(404)

        drink.delete()

        return jsonify({
            'success': True,
            'delete': drink_id
        })
    except:
        abort(400)


# ----------------------------------------------
# Error Handling
# ----------------------------------------------
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
        }), 422


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
        }), 404


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "Bad Request"
        }), 400


@app.errorhandler(405)
def not_allowed(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": 'Method Not Allowed'
    }), 405


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": "Not Authorized"
        }), 401


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": 'Internal Server Error'
    }), 500


#  error handler for AuthError
@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error
    }), error.status_code
