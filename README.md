# .NET MAUI Android Widget Demo

Projekt przykładowy aplikacji **.NET MAUI (.NET 8.0)** przygotowany do uruchomienia i kompilacji w **Visual Studio 2022 / Visual Studio 2026 Preview**, demonstrujący integrację z rdzennymi widgetami ekranu głównego (Home Screen App Widgets) w systemie Android.

---

## 🚀 Architektura i Sposób Działania

Aplikacja demonstruje dwa podstawowe mechanizmy pracy z widgetami Androida z poziomu C#/.NET MAUI:

1. **Ręczne dodawanie widgetu** – Użytkownik przytrzymuje puste miejsce na ekranie startowym Androida, przechodzi do sekcji *Widgety*, wybiera `MauiAppWidgetDemo` i przeciąga widget na pulpit.
2. **Programowe przypinanie widgetu (Programmatic Pinning)** – Wykorzystanie interfejsu API Androida O+ (`AppWidgetManager.RequestPinAppWidget`), pozwalającego na wyświetlenie monitu instalacji widgetu z poziomu samej aplikacji MAUI po kliknięciu przycisku.

---

## 📁 Struktura Projektu

* **`Platforms/Android/SampleWidgetProvider.cs`**
  * Klasa dziedzicząca po `AppWidgetProvider` (będąca w istocie odbiorcą komunikatów `BroadcastReceiver`).
  * Reaguje nazdarzenia systemowe `APPWIDGET_UPDATE` oraz własne zdarzenie kliknięcia w przycisk widgetu `ACTION_WIDGET_BUTTON`.
  * Aktualizuje widok widgetu przy pomocy klasy `RemoteViews`.

* **`Platforms/Android/Resources/layout/sample_widget.xml`**
  * Układ interfejsu użytkownika widgetu zdefiniowany w natywnym XML Androida (przycisk odświeżania, nagłówek, etykiety stanu i czasu).

* **`Platforms/Android/Resources/xml/sample_widget_info.xml`**
  * Plik konfigurujący metadane widgetu (minimalny rozmiar widgetu, częstotliwość automatycznych aktualizacji systemowych, identyfikator szablonu).

* **`Platforms/Android/AndroidManifest.xml`**
  * Rejestracja odbiorcy `SampleWidgetProvider` w systemie Android wraz z filrem intencji (`intent-filter`) i wskazaniem metadanych.

* **`WidgetService.cs` & `Platforms/Android/WidgetService.cs`**
  * Statyczna klasa częściowa (partial class) udostępniająca uniwersalny interfejs C# do komunikacji z systemem Android:
    * `WidgetService.RequestPinWidget()` – uruchamia prośbę o dodanie widgetu na pulpit.
    * `WidgetService.UpdateWidgetData()` – wysyła sygnał odświeżenia danych do wszystkich aktywnych instancji widgetu.

* **`MainPage.xaml` & `MainPage.xaml.cs`**
  * Strona główna aplikacji .NET MAUI prezentująca przyciski interakcji z widgetem oraz status.

---

## 🛠 Wyagania i Uruchamianie

### Wymagania:
* **Visual Studio 2022 (v17.8+)** lub **Visual Studio 2026**
* Zainstalowany obciążenie (workload) **.NET Multi-platform App UI (.NET MAUI)**
* SDK Androida z obsługą API 21+ (rekomendowane Android 14 / API 34)

### Jak uruchomić projekt w Visual Studio:
1. Otwórz solucję / projekt `MauiAppWidgetDemo.csproj` w Visual Studio.
2. Wybierz jako docelową platformę **Android Emulator** lub fizyczne urządzenie z Androidem podłączone przez USB / Wi-Fi debugging.
3. Naciśnij **F5** (lub kliknij *Start Debugging*).

---

## 📱 Jak przetestować widget na urządzeniu / emulatorze Androida

1. **Uruchom aplikację MAUI.**
2. Kliknij przycisk **📌 Przypnij Widget do Ekranu Głównego**:
   * Jeśli urządzenie działa na Androidzie 8.0 (API 26) lub nowszym, pojawi się systemowe okno z prośbą o potwierdzenie dodania widgetu na ekran główny.
3. Wypróbuj przycisk **🔄 Zaktualizuj Dane Widgetu** w aplikacji:
   * Tekst oraz czas ostatniej aktualizacji na widgecie na pulpicie zmienią się w czasie rzeczywistym.
4. Kliknij przycisk **🔄 Odśwież Dane** z poziomu samego widgetu na pulpicie Androida:
   * Licznik kliknięć na widgecie zwiększy się automatycznie bez konieczności otwierania aplikacji głównej.
