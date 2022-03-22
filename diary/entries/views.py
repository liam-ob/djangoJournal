from django.shortcuts import render
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from .models import Entry, Login
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin

# Create your views here.


class LockedView(LoginRequiredMixin, DetailView):
    model = Login
    login_url = "admin:login"


class EntryListView(LoginRequiredMixin, ListView):
    model = Entry
    queryset = Entry.objects.all().order_by("-date_created")


class EntryDetailView(LoginRequiredMixin, DetailView):
    model = Entry


class EntryCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    model = Entry
    fields = ["title", "content"]
    success_url = reverse_lazy('entry-list')
    success_message = "you created a fucking entry!\nyou fucking gronk ass stinka"


class EntryUpdateView(LoginRequiredMixin, UpdateView, SuccessMessageMixin):
    model = Entry
    fields = ['title', 'content']
    success_message = "you just managed to update a entry fool"

    def get_success_url(self):
        return reverse_lazy(
            "entry-detail",
            kwargs={"pk": self.entry.id}
        )


class EntryDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = Entry
    success_url = reverse_lazy('entry-list')
    success_message = "that message is now deleted\nFool!"

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, self.success_message)
        return super().delete(request, *args, **kwargs)