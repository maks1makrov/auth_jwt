from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View
from rest_framework import status, generics
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .forms import CustomResetPSWForm
from .models import User
from .renderers import UserJSONRenderer
from .serializers import RegistrationSerializer, LoginSerializer, UserSerializer, ResetPasswordEmailRequestSerializer
from .token_for_activate import account_activation_token


class RegistrationAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    renderer_classes = (UserJSONRenderer,)

    def post(self, request):
        user = request.data.get('user', {})

        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        current_site = get_current_site(request)
        mail_subject = 'Activation link has been sent to your email id'
        message = render_to_string('acc_active_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.email)),
            'token': account_activation_token.make_token(user),
        })

        email = EmailMessage(
            mail_subject, message, to=[user.email]
        )
        email.send()

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = LoginSerializer

    def post(self, request):
        user = request.data.get('user', {})
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = UserSerializer

    def retrieve(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        serializer_data = request.data.get('user', {})

        serializer = self.serializer_class(
            request.user, data=serializer_data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            current_site = get_current_site(request)
            mail_subject = 'Use link below to reset your password'
            message = render_to_string('acc_reset_psw.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.email)),
                'token': account_activation_token.make_token(user),
            })

            email = EmailMessage(
                mail_subject, message, to=[user.email]
            )
            email.send()
        else:
            Response({'error': 'user with this email do not exist'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


def activate(request, uidb64, token):
    try:
        email = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(email=email)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


def resetget(request, uidb64, token):
    try:
        email = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(email=email)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        form = CustomResetPSWForm()
        return render(request, "reset.html", {"form": form})
    else:
        return HttpResponse('Activation link is invalid!')

# class ResetView(View):
    # def get(self, request, uidb64, token):
    #     try:
    #         email = force_str(urlsafe_base64_decode(uidb64))
    #         user = User.objects.get(email=email)
    #     except(TypeError, ValueError, OverflowError, User.DoesNotExist):
    #         user = None
    #     if user is not None and account_activation_token.check_token(user, token):
    #         form = CustomResetPSWForm()
    #         return render(request, "reset.html", {"form": form})
    #     else:
    #         return HttpResponse('Activation link is invalid!')

def reset(request):
    form = CustomResetPSWForm(data=request.POST)
    if form.is_valid():
        psw = form.password
        user = User.objects.get(email=form.email)
        user.set_password(psw)
        return HttpResponse('success for reset password')
    messages.error(request, "error")
    return HttpResponse('error for reset password')
