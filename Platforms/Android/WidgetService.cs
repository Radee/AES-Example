#if ANDROID
using Android.Appwidget;
using Android.Content;
using Android.OS;

namespace MauiAppWidgetDemo;

public static partial class WidgetService
{
	public static partial void RequestPinWidget()
	{
		var context = Android.App.Application.Context;
		var appWidgetManager = AppWidgetManager.GetInstance(context);

		if (appWidgetManager == null)
			return;

		var myProvider = new ComponentName(context, Java.Lang.Class.FromType(typeof(SampleWidgetProvider)));

		if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
		{
			if (appWidgetManager.IsRequestPinAppWidgetSupported)
			{
				appWidgetManager.RequestPinAppWidget(myProvider, null, null);
			}
		}
	}

	public static partial void UpdateWidgetData()
	{
		var context = Android.App.Application.Context;
		var appWidgetManager = AppWidgetManager.GetInstance(context);

		if (appWidgetManager == null)
			return;

		var myProvider = new ComponentName(context, Java.Lang.Class.FromType(typeof(SampleWidgetProvider)));
		var appWidgetIds = appWidgetManager.GetAppWidgetIds(myProvider);

		foreach (var widgetId in appWidgetIds)
		{
			SampleWidgetProvider.UpdateAppWidget(context, appWidgetManager, widgetId, "Zaktualizowano z MAUI App!");
		}
	}
}
#else
namespace MauiAppWidgetDemo;

public static partial class WidgetService
{
	public static partial void RequestPinWidget()
	{
	}

	public static partial void UpdateWidgetData()
	{
	}
}
#endif
