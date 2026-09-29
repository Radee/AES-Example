namespace MauiAppWidgetDemo;

public partial class MainPage : ContentPage
{
	public MainPage()
	{
		InitializeComponent();
	}

	private void OnPinWidgetClicked(object sender, EventArgs e)
	{
		WidgetService.RequestPinWidget();
	}

	private void OnUpdateWidgetClicked(object sender, EventArgs e)
	{
		WidgetService.UpdateWidgetData();
		StatusLabel.Text = $"Ostatnia aktualizacja: {DateTime.Now:HH:mm:ss}";
	}
}
