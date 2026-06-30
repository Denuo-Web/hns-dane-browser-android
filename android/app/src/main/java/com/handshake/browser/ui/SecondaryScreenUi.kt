package com.handshake.browser.ui

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity

internal fun ComponentActivity.setSecondaryScreen(
    title: String,
    content: LinearLayout.() -> Unit,
) {
    val root = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.START
        setPadding(uiDp(20), uiDp(20), uiDp(20), uiDp(20))
        applySystemBarPadding()
        addView(screenHeading(title))
        content()
    }

    setContentView(
        ScrollView(this).apply {
            addView(root, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
        },
    )
}

internal fun Context.screenSection(
    title: String,
    content: LinearLayout.() -> Unit,
): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, uiDp(10), 0, uiDp(12))
        addView(sectionHeading(title))
        content()
    }

internal fun LinearLayout.addScreenRow(row: View) {
    addView(row, LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ))
    addView(screenDivider())
}

internal fun Context.preferenceRow(
    title: String,
    summary: String? = null,
    summaryView: TextView? = null,
    actionLabel: String? = null,
    destructive: Boolean = false,
    selectableSummary: Boolean = false,
    summaryMaxLines: Int = 3,
    action: (() -> Unit)? = null,
): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = uiDp(64)
        setPadding(0, uiDp(10), 0, uiDp(10))
        if (action != null) {
            isClickable = true
            isFocusable = true
            applyScreenSelectableBackground()
            setOnClickListener { action() }
        }

        val labels = LinearLayout(this@preferenceRow).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, uiDp(12), 0)
            addView(preferenceTitle(title))
            val detail = summaryView ?: summary?.let {
                preferenceSummary(
                    text = it,
                    selectable = selectableSummary,
                    maxLines = summaryMaxLines,
                )
            }
            if (detail != null) {
                addView(detail)
            }
        }
        addView(labels, LinearLayout.LayoutParams(
            0,
            LinearLayout.LayoutParams.WRAP_CONTENT,
            1f,
        ))

        if (actionLabel != null) {
            addView(preferenceActionLabel(actionLabel, destructive))
        }
    }

internal fun Context.checkboxRow(
    title: String,
    summaryView: TextView,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, uiDp(8), 0, uiDp(10))
        addView(CheckBox(this@checkboxRow).apply {
            text = title
            textSize = 16f
            setTextColor(ScreenColors.PRIMARY_TEXT)
            setPadding(0, 0, 0, 0)
            isChecked = checked
            setOnCheckedChangeListener { _, value -> onCheckedChange(value) }
        })
        addView(summaryView, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply {
            leftMargin = uiDp(36)
        })
    }

internal fun Context.preferenceSummary(
    text: String,
    selectable: Boolean = false,
    maxLines: Int = 3,
): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 14f
        setTextColor(ScreenColors.SECONDARY_TEXT)
        this.maxLines = maxLines
        ellipsize = if (maxLines == Int.MAX_VALUE) null else TextUtils.TruncateAt.END
        setTextIsSelectable(selectable)
        setPadding(0, uiDp(3), 0, 0)
    }

internal fun Context.reportText(
    text: String,
    monospace: Boolean = false,
): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 14f
        setTextColor(ScreenColors.PRIMARY_TEXT)
        if (monospace) {
            typeface = Typeface.MONOSPACE
            textSize = 13f
        }
        setTextIsSelectable(true)
        setPadding(0, uiDp(8), 0, uiDp(12))
    }

internal fun Context.screenHeading(text: String): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 28f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(ScreenColors.PRIMARY_TEXT)
        setPadding(0, 0, 0, uiDp(10))
    }

internal fun Context.sectionHeading(text: String): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 13f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(ScreenColors.SECONDARY_TEXT)
        setPadding(0, uiDp(18), 0, uiDp(6))
    }

internal fun Context.preferenceTitle(text: String): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 16f
        setTextColor(ScreenColors.PRIMARY_TEXT)
        maxLines = 2
        ellipsize = TextUtils.TruncateAt.END
    }

internal fun Context.preferenceActionLabel(text: String, destructive: Boolean): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 14f
        typeface = Typeface.DEFAULT_BOLD
        gravity = Gravity.CENTER_VERTICAL or Gravity.END
        minWidth = uiDp(56)
        maxLines = 1
        ellipsize = TextUtils.TruncateAt.END
        setTextColor(
            if (destructive) {
                ScreenColors.DESTRUCTIVE
            } else {
                ScreenColors.ACTION
            },
        )
    }

internal fun View.screenDivider(): View =
    View(context).apply {
        setBackgroundColor(ScreenColors.DIVIDER)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            1,
        )
    }

internal fun View.applyScreenSelectableBackground() {
    val typedValue = TypedValue()
    context.theme.resolveAttribute(android.R.attr.selectableItemBackground, typedValue, true)
    if (typedValue.resourceId != 0) {
        setBackgroundResource(typedValue.resourceId)
    }
}

internal fun Context.uiDp(value: Int): Int =
    (value * resources.displayMetrics.density + 0.5f).toInt()

private object ScreenColors {
    val PRIMARY_TEXT: Int = Color.rgb(32, 33, 36)
    val SECONDARY_TEXT: Int = Color.rgb(95, 99, 104)
    val ACTION: Int = Color.rgb(21, 101, 192)
    val DESTRUCTIVE: Int = Color.rgb(183, 28, 28)
    val DIVIDER: Int = Color.rgb(218, 220, 224)
}
