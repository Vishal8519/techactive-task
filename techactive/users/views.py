from datetime import timedelta

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
class GenerateToken(APIView):
    def post(self, request):
        serializer = YourTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh = RefreshToken.for_user(serializer.validated_data['user'])

        token = {
            'access': str(refresh.access_token),
            'expires_in': str(timedelta(minutes=3)),
        }

        return Response(token, status=status.HTTP_200_OK)


from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import User
from datetime import datetime, timedelta
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Dictionary to store request counts and timestamps
request_counts = {}

class InsertUserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        access_token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
        user = request.user

        f_name = request.POST.get('f_name')
        l_name = request.POST.get('l_name')
        email_id = request.POST.get('email_id')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')
        created_date = datetime.now()

        if not f_name or not l_name or not email_id or not phone_number or not address:
            return JsonResponse({'error': 'One or more required fields missing'}, status=400)

        # Check if the user has exceeded the request limit
        user_ip = request.META.get('REMOTE_ADDR')
        if user_ip not in request_counts:
            request_counts[user_ip] = [1, datetime.now()]
        else:
            count, last_request_time = request_counts[user_ip]
            time_since_last_request = datetime.now() - last_request_time

            # Reset the request count and timestamp if the time since the last request is more than 1 minute
            if time_since_last_request > timedelta(minutes=1):
                request_counts[user_ip] = [1, datetime.now()]
            # Return an error message if the user has exceeded the request limit
            elif count >= 5:
                return JsonResponse({'error': 'Request limit exceeded. Try again after 1 minute.'}, status=429)
            # Update the request count and timestamp if the user has not exceeded the request limit
            else:
                request_counts[user_ip] = [count + 1, last_request_time]

        try:
            user = User.objects.create(
                f_name=f_name,
                l_name=l_name,
                email_id=email_id,
                phone_number=phone_number,
                address=address,
                created_date=created_date
            )
            user.save()

            return JsonResponse({'message': 'User created successfully'}, status=201)
        except:
            return JsonResponse({'error': 'User creation failed'}, status=500)


