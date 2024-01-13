package main

func (w *Window) createLocalTermTab() {
	tab := NewLocalTerm()
	w.addTermTab(tab)
}
