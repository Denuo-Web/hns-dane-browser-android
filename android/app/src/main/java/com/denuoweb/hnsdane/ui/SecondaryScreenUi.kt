package com.denuoweb.hnsdane.ui

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.text.SpannableString
import android.text.Spanned
import android.text.TextUtils
import android.text.style.StyleSpan
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import kotlin.math.abs

internal fun ComponentActivity.setSecondaryScreen(
    title: String,
    onSwipeLeft: (() -> Unit)? = null,
    onSwipeRight: (() -> Unit)? = null,
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
            installHorizontalSwipeNavigation(onSwipeLeft, onSwipeRight)
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
    boldSummary: Boolean = false,
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
                    bold = boldSummary,
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
    bold: Boolean = false,
): TextView =
    TextView(this).apply {
        this.text = text
        textSize = 14f
        if (bold) {
            typeface = Typeface.DEFAULT_BOLD
        }
        setTextColor(ScreenColors.SECONDARY_TEXT)
        this.maxLines = maxLines
        ellipsize = if (maxLines == Int.MAX_VALUE) null else TextUtils.TruncateAt.END
        setTextIsSelectable(selectable)
        setPadding(0, uiDp(3), 0, 0)
    }

internal fun Context.reportText(
    text: String,
    monospace: Boolean = false,
    boldFieldValues: Boolean = false,
): TextView =
    TextView(this).apply {
        this.text = if (boldFieldValues) text.withBoldFieldValues() else text
        textSize = 14f
        setTextColor(ScreenColors.PRIMARY_TEXT)
        if (monospace) {
            typeface = Typeface.MONOSPACE
            textSize = 13f
        }
        setTextIsSelectable(true)
        setPadding(0, uiDp(8), 0, uiDp(12))
    }

internal fun Context.fieldReportText(text: String): TextView =
    reportText(text, boldFieldValues = true)

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

@SuppressLint("ClickableViewAccessibility")
private fun View.installHorizontalSwipeNavigation(
    onSwipeLeft: (() -> Unit)?,
    onSwipeRight: (() -> Unit)?,
) {
    if (onSwipeLeft == null && onSwipeRight == null) {
        return
    }

    var downX = 0f
    var downY = 0f
    setOnTouchListener { _, event ->
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                downX = event.x
                downY = event.y
            }
            MotionEvent.ACTION_UP -> {
                val deltaX = event.x - downX
                val deltaY = event.y - downY
                if (abs(deltaX) >= context.uiDp(72) && abs(deltaX) > abs(deltaY) * 1.5f) {
                    if (deltaX < 0) {
                        onSwipeLeft?.invoke()
                    } else {
                        onSwipeRight?.invoke()
                    }
                    return@setOnTouchListener true
                }
            }
        }
        false
    }
}

private fun String.withBoldFieldValues(): SpannableString {
    val styled = SpannableString(this)
    var lineStart = 0
    while (lineStart < length) {
        val lineEnd = indexOf('\n', lineStart)
            .takeIf { it >= 0 }
            ?: length
        val colon = indexOf(':', lineStart)
            .takeIf { it >= lineStart && it < lineEnd }
        if (colon != null) {
            val valueStart = skipSpaces(colon + 1, lineEnd)
            styled.bold(valueStart, lineEnd)
        } else {
            styled.boldKeyValueData(lineStart, lineEnd, this)
        }
        lineStart = lineEnd + 1
    }
    return styled
}

private fun String.skipSpaces(start: Int, end: Int): Int {
    var index = start
    while (index < end && this[index].isWhitespace()) {
        index += 1
    }
    return index
}

private fun SpannableString.boldKeyValueData(lineStart: Int, lineEnd: Int, source: String) {
    var cursor = lineStart
    while (cursor < lineEnd) {
        val equals = source.indexOf('=', cursor)
            .takeIf { it >= cursor && it < lineEnd }
            ?: return
        val valueStart = equals + 1
        val comma = source.indexOf(',', valueStart)
            .takeIf { it >= valueStart && it < lineEnd }
            ?: lineEnd
        bold(valueStart, comma)
        cursor = comma + 1
    }
}

private fun SpannableString.bold(start: Int, end: Int) {
    if (start < end) {
        setSpan(StyleSpan(Typeface.BOLD), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }
}

private object ScreenColors {
    val PRIMARY_TEXT: Int = Color.rgb(32, 33, 36)
    val SECONDARY_TEXT: Int = Color.rgb(95, 99, 104)
    val ACTION: Int = Color.rgb(21, 101, 192)
    val DESTRUCTIVE: Int = Color.rgb(183, 28, 28)
    val DIVIDER: Int = Color.rgb(218, 220, 224)
}
