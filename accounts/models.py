from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save


# Create your models here.
class Profile(models.Model):
	user=models.OneToOneField(User)
	bio = models.TextField(max_length=300, default='')
	address=models.TextField(max_length=100, default='')
	phone_number = models.CharField(max_length=12,default='')
	profile_picture=models.ImageField(upload_to='profile_picture/',blank=True)

	def __str__(self):
		return self.user.username

def create_profile(sender, **kwargs):
	if kwargs['created']:
		user_profile=Profile.objects.create(user=kwargs['instance'])

post_save.connect(create_profile, sender=User)