from pathlib import Path
from decouple import config
import dj_database_url
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')

# Database configuration for Render (PostgreSQL)
DATABASE_URL = config('DATABASE_URL', default=None)
if not DATABASE_URL:
    raise ValueError('DATABASE_URL environment variable is not set')
DATABASES = {
    'default': dj_database_url.config(
        default=DATABASE_URL,
        conn_max_age=600,
        ssl_require=True
    )
}

# Debug prints to verify configuration
print("DATABASE_URL:", DATABASE_URL)
print("DATABASES:", DATABASES)
print("SECRET_KEY:", SECRET_KEY)
print("ALLOWED_HOSTS:", ALLOWED_HOSTS)
print("DEBUG:", DEBUG)


# Application definition


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'roles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'roles_project.urls'

# settings.py configuration for email backend
# This configuration is for using Gmail's SMTP server to send emails.

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'  # Gmail SMTP server
EMAIL_PORT = 587  # Port for TLS
EMAIL_USE_TLS = True  # Enable TLS
EMAIL_USE_SSL = False  # SSL should be false if TLS is true
EMAIL_HOST_USER = 'peanutchess091@gmail.com'  # Your Gmail address
EMAIL_HOST_PASSWORD = 'oxvk gupz tncs nxrc'  # Your app-specific password (see note below)
DEFAULT_FROM_EMAIL = 'noreply.kuetevaldes@gmail.com'  # Default from email address


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
        'roles': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'ERROR',
            'propagate': False,
        },
    },
}


CSRF_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_SECURE = True  # Ensure you're using HTTPS in production

# Make sure session data persists
SESSION_ENGINE = 'django.contrib.sessions.backends.db'


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'roles' / 'templates',
            BASE_DIR / 'templates',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'roles_project.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

# New settings.py from migration from sqlite to postsql
# New settings.py from migration from sqlite to postsql
# Remove or comment out this block

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'rolesdb_test',
        'USER': 'postgres',
        'PASSWORD': 'Chess6988',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}



# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'roles.User'

user = AUTH_USER_MODEL
LOGIN_URL = 'roles:signin'  # Updated to match existing URL pattern
LOGOUT_REDIRECT_URL = 'roles:signin'  # Redirect to signin page after logout
AUTHENTICATION_BACKENDS = ['django.contrib.auth.backends.ModelBackend']



#pytest roles/test_forms.py