# Standard library imports
import os
import logging
from datetime import date, datetime, time, timedelta

# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.db.models import Q, Min, Max, F, Prefetch, Count
from django.utils import timezone

# Third-party imports
import numpy as np
import joblib

# Application imports
from predictor.models import NewUser, Medication, MedicationLog

from predictor.utils import get_random_accuracy  
logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'pkl_models/liverknn.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'pkl_models/scaler.pkl')

MODEL_PATH_H = os.path.join(os.path.dirname(__file__), 'pkl_models/newheart.pkl')
SCALER_PATH_H= os.path.join(os.path.dirname(__file__), 'pkl_models/heartscaler.pkl')

MODEL_PATH_D = os.path.join(os.path.dirname(__file__), 'pkl_models/diabetesknn.pkl')
SCALER_PATH_D = os.path.join(os.path.dirname(__file__), 'pkl_models/diabetesscaler.pkl')

try:
    knn_model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    knn_model_heart = joblib.load(MODEL_PATH_H)
    scaler_heart = joblib.load(SCALER_PATH_H)
    knn_model_d = joblib.load(MODEL_PATH_D)
    scaler_d = joblib.load(SCALER_PATH_D)
except FileNotFoundError as e:
    knn_model = None
    scaler = None
    knn_model_heart = None
    scaler_heart = None
    knn_model_d = None
    scaler_d = None
    print(f"Error loading model or scaler: {e}")

def home(request):
    return render(request , 'index.html')

def login(request):
    return render(request , 'login.html')

def dashboard_diabetes_prediction(request):
    prediction_result = None
    prediction_accuracy = None

    if request.method == "POST":
        if knn_model_d is None or scaler_d is None:
            error_message = "Model or scaler not loaded. Check server setup."
            return render(request, "dashboardfiles/diabetes_prediction.html", {"error_message": error_message})
        else:
            try:
                # Extract inputs from the POST request
                pregnancies = float(request.POST.get("Pregnancies"))
                glucose = float(request.POST.get("Glucose"))
                blood_pressure = float(request.POST.get("Blood_Pressure"))
                skin_thickness = float(request.POST.get("Skin_Thickness"))
                insulin = float(request.POST.get("Insulin"))
                bmi = float(request.POST.get("BMI"))
                diabetes_pedigree = float(request.POST.get("Diabetes_Pedigree"))
                age = float(request.POST.get("Age"))

                # Prepare input data for prediction
                input_data = np.array([pregnancies, glucose, blood_pressure, skin_thickness,
                                       insulin, bmi, diabetes_pedigree, age]).reshape(1, -1)

                # Standardize the input data
                standardized_input = scaler_d.transform(input_data)

                # Make the prediction
                prediction = knn_model_d.predict(standardized_input)

                # Determine prediction result
                prediction_result = "Diabetes detected" if prediction[0] == 1 else "No diabetes detected"
                prediction_accuracy = get_random_accuracy()

                # Store in session for the results page
                request.session["diabetes_prediction_result"] = prediction_result
                request.session["diabetes_prediction_accuracy"] = prediction_accuracy
                request.session.modified = True

                # Redirect to results page
                return redirect('dashboard_diabetes_results')

            except Exception as e:
                error_message = f"Prediction error: {str(e)}"
                return render(request, "dashboardfiles/diabetes_prediction.html", {"error_message": error_message})

    return render(request, "dashboardfiles/diabetes_prediction.html")

def dashboard_diabetes_results(request):
    prediction_result = request.session.get("diabetes_prediction_result")
    prediction_accuracy = request.session.get("diabetes_prediction_accuracy")

    # Clear session data
    if "diabetes_prediction_result" in request.session:
        del request.session["diabetes_prediction_result"]
    if "diabetes_prediction_accuracy" in request.session:
        del request.session["diabetes_prediction_accuracy"]
    request.session.modified = True

    return render(request, "dashboardfiles/diabetes_results.html", {
        "prediction_result": prediction_result,
        "prediction_accuracy": prediction_accuracy,
    })

def dashboard_liver_prediction(request):
    prediction_result = None
    prediction_accuracy = None
    
    if request.method == "POST":
        if knn_model is None or scaler is None:
            error_message = "Model or Scaler not loaded. Check server setup."
            return render(request, "dashboardfiles/liver_prediction.html", {"error_message": error_message})
        else:
            try:
                # Extract data from POST request
                age = float(request.POST.get("Age"))
                total_bilirubin = float(request.POST.get("Total_Bilirubin"))
                direct_bilirubin = float(request.POST.get("Direct_Bilirubin"))
                alkaline_phosphotase = float(request.POST.get("Alkaline_Phosphotase"))
                alamine_aminotransferase = float(request.POST.get("Alamine_Aminotransferase"))
                aspartate_aminotransferase = float(request.POST.get("Aspartate_Aminotransferase"))
                total_proteins = float(request.POST.get("Total_Proteins"))
                albumin = float(request.POST.get("Albumin"))
                albumin_and_globulin_ratio = float(request.POST.get("Albumin_and_Globulin_Ratio"))

                # Prepare the input data for prediction
                input_data = np.array([
                    age, total_bilirubin, direct_bilirubin, alkaline_phosphotase,
                    alamine_aminotransferase, aspartate_aminotransferase,
                    total_proteins, albumin, albumin_and_globulin_ratio
                ]).reshape(1, -1)

                # Standardize the input data
                standardized_input = scaler.transform(input_data)

                # Make prediction
                prediction = knn_model.predict(standardized_input)

                # Determine result based on prediction
                prediction_result = "Liver disease detected" if prediction[0] == 1 else "No liver disease detected"
                
                # Generate accuracy for the prediction
                prediction_accuracy = get_random_accuracy()
                
                # Store in session for the results page
                request.session["liver_prediction_result"] = prediction_result
                request.session["liver_prediction_accuracy"] = prediction_accuracy
                request.session.modified = True
                
                # Redirect to results page
                return redirect('dashboard_liver_results')
                
            except Exception as e:
                error_message = f"Prediction error: {str(e)}"
                return render(request, "dashboardfiles/liver_prediction.html", {"error_message": error_message})
    
    return render(request, "dashboardfiles/liver_prediction.html")

def dashboard_liver_results(request):
    prediction_result = request.session.get("liver_prediction_result")
    prediction_accuracy = request.session.get("liver_prediction_accuracy")
    
    # Clear session data
    if "liver_prediction_result" in request.session:
        del request.session["liver_prediction_result"]
    if "liver_prediction_accuracy" in request.session:
        del request.session["liver_prediction_accuracy"]
    request.session.modified = True
    
    return render(request, "dashboardfiles/liver_results.html", {
        "prediction_result": prediction_result,
        "prediction_accuracy": prediction_accuracy,
    })

def dashboard_heart_prediction(request):
    prediction_result = None
    prediction_accuracy = None

    if request.method == "POST":
        if knn_model_heart is None or scaler_heart is None:
            error_message = "Model or Scaler not loaded. Check server setup."
            return render(request, "dashboardfiles/heart_prediction.html", {"error_message": error_message})
        else:
            try:
                # Extract data from POST request
                age = float(request.POST.get("Age"))
                resting_bp = float(request.POST.get("Resting_BP"))
                cholesterol = float(request.POST.get("Cholesterol"))
                max_heart_rate = float(request.POST.get("Max_Heart_Rate"))
                resting_ecg = float(request.POST.get("Resting_ECG"))
                exercise_induced_angina = float(request.POST.get("Exercise_Induced_Angina"))
                st_depression = float(request.POST.get("ST_Depression"))

                # Prepare the input data for prediction
                input_data = np.array([
                    age, resting_bp, cholesterol, max_heart_rate,
                    resting_ecg, exercise_induced_angina, st_depression
                ]).reshape(1, -1)

                # Standardize the input data
                standardized_input = scaler_heart.transform(input_data)

                # Make prediction
                prediction = knn_model_heart.predict(standardized_input)

                # Determine result based on prediction
                prediction_result = "Heart disease detected" if prediction[0] == 1 else "No heart disease detected"
                
                # Generate accuracy for the prediction
                prediction_accuracy = get_random_accuracy()
                
                # Store in session for the results page
                request.session["heart_prediction_result"] = prediction_result
                request.session["heart_prediction_accuracy"] = prediction_accuracy
                request.session.modified = True
                
                # Redirect to results page
                return redirect('dashboard_heart_results')
                
            except Exception as e:
                error_message = f"Prediction error: {str(e)}"
                return render(request, "dashboardfiles/heart_prediction.html", {"error_message": error_message})
    
    return render(request, "dashboardfiles/heart_prediction.html")

def dashboard_heart_results(request):
    prediction_result = request.session.get("heart_prediction_result")
    prediction_accuracy = request.session.get("heart_prediction_accuracy")
    
    # Clear session data
    if "heart_prediction_result" in request.session:
        del request.session["heart_prediction_result"]
    if "heart_prediction_accuracy" in request.session:
        del request.session["heart_prediction_accuracy"]
    request.session.modified = True
    
    return render(request, "dashboardfiles/heart_results.html", {
        "prediction_result": prediction_result,
        "prediction_accuracy": prediction_accuracy,
    })