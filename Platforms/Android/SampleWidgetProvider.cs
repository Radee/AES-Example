using Android.App;
using Android.Appwidget;
using Android.Content;
using Android.Widget;

namespace MauiAppWidgetDemo;

[BroadcastReceiver(Label = "MAUI Demo Widget", Exported = true)]
[IntentFilter(new[] { AppWidgetManager.ActionAppwidgetUpdate, ActionWidgetButton })]
[MetaData("android.appwidget.provider", Resource = "@xml/sample_widget_info")]
public class SampleWidgetProvider : AppWidgetProvider
{
	public const string ActionWidgetButton = "com.companyname.mauiappwidgetdemo.ACTION_WIDGET_BUTTON";
	private static int _clickCounter = 0;

	public override void OnUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds)
	{
		base.OnUpdate(context, appWidgetManager, appWidgetIds);

		foreach (var appWidgetId in appWidgetIds)
		{
			UpdateAppWidget(context, appWidgetManager, appWidgetId);
		}
	}

	public override void OnReceive(Context context, Intent intent)
	{
		base.OnReceive(context, intent);

		if (intent.Action == ActionWidgetButton)
		{
			_clickCounter++;
			var appWidgetManager = AppWidgetManager.GetInstance(context);
			if (appWidgetManager != null)
			{
				var componentName = new ComponentName(context, Java.Lang.Class.FromType(typeof(SampleWidgetProvider)));
				var appWidgetIds = appWidgetManager.GetAppWidgetIds(componentName);

				foreach (var appWidgetId in appWidgetIds)
				{
					UpdateAppWidget(context, appWidgetManager, appWidgetId, $"Kliknięcia: {_clickCounter}");
				}
			}
		}
	}

	public static void UpdateAppWidget(Context context, AppWidgetManager appWidgetManager, int appWidgetId, string? customStatus = null)
	{
		var views = new RemoteViews(context.PackageName, Resource.Layout.sample_widget);

		string timeString = DateTime.Now.ToString("HH:mm:ss");
		string statusText = customStatus ?? "Widget aktywny!";

		views.SetTextViewText(Resource.Id.widget_status, statusText);
		views.SetTextViewText(Resource.Id.widget_updated_time, $"Ostatnia akt.: {timeString}");

		// Intencja przycisku
		var intent = new Intent(context, typeof(SampleWidgetProvider));
		intent.SetAction(ActionWidgetButton);

		var pendingIntent = PendingIntent.GetBroadcast(
			context,
			0,
			intent,
			PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable
		);

		views.SetOnClickPendingIntent(Resource.Id.widget_button, pendingIntent);

		appWidgetManager.UpdateAppWidget(appWidgetId, views);
	}
}
